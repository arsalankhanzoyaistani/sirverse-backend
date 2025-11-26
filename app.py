# ✅ backend/app.py - COMPLETE UPDATED CODE FOR YOUR DATABASE SCHEMA
import eventlet
eventlet.monkey_patch()

import os, random, hashlib
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
import bcrypt
import re

# ------------------------------------------------
# Load environment variables
# ------------------------------------------------
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")

# ------------------------------------------------
# Flask app setup
# ------------------------------------------------
app = Flask(__name__)

# Fix DB URL for Railway
db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)

# App config
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "change-this"),
    JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY", "jwt-change-this"),
    SQLALCHEMY_DATABASE_URI=db_url or "postgresql+psycopg2://sirverse_user:sirverse123@localhost:5432/sirverse_gpt_db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

# ------------------------------------------------
# Initialize extensions
# ------------------------------------------------
from config.database import init_db, db
init_db(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# ------------------------------------------------
# CORS setup - UPDATED FOR LOCAL DEVELOPMENT
# ------------------------------------------------

CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Type", "Authorization"]
)


# SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
connected_users = {}

# Cloudinary config
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True,
)

print("✅ Flask, Database, JWT, CORS, and SocketIO initialized successfully.")
print("🚀 SirVerse GPT backend starting...")

# ------------------------------------------------
# Password Helper Functions
# ------------------------------------------------
def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email:
        return True  # Email is optional in your schema
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone: str) -> bool:
    """Validate phone number format"""
    if not phone:
        return True  # Phone is optional in your schema
    pattern = r'^\+?1?\d{9,15}$'
    return re.match(pattern, phone) is not None

# ------------------------------------------------
# Updated User Model matching your database schema
# ------------------------------------------------

# 1. Define Post model FIRST
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

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "post_id", name="_user_post_unique"),)

class Reel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    video_url = db.Column(db.String(500), nullable=False)
    caption = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes_count = db.Column(db.Integer, default=0)

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

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    is_group = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    participants = db.relationship(
        "ChatParticipant",
        backref="room",
        cascade="all,delete-orphan",
        lazy=True
    )

class ChatParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)
    related_id = db.Column(db.Integer, nullable=True)  # post_id, user_id, etc.
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("follower_id", "following_id", name="_follower_following_unique"),)

class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("blocker_id", "blocked_id", name="_blocker_blocked_unique"),)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reported_post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=True)
    reported_reel_id = db.Column(db.Integer, db.ForeignKey("reel.id"), nullable=True)
    report_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AIHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    role = db.Column(db.String(10))
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 2. NOW define User model AFTER all other models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone = db.Column(db.String(30), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=True)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    class_level = db.Column(db.String(10), nullable=True)
    avatar = db.Column(db.String(255), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Relationships - NOW these will work because all models are defined
    posts = db.relationship("Post", backref="user", lazy=True)
    reels = db.relationship("Reel", backref="user", lazy=True)
    comments = db.relationship("Comment", backref="user", lazy=True)
    likes = db.relationship("Like", backref="user", lazy=True)
    follower = db.relationship("Follow", foreign_keys=[Follow.follower_id], backref="follower_user")
    following = db.relationship("Follow", foreign_keys=[Follow.following_id], backref="following_user")
    blocker = db.relationship("Block", foreign_keys=[Block.blocker_id])
    blocked = db.relationship("Block", foreign_keys=[Block.blocked_id])
    reports_made = db.relationship("Report", foreign_keys=[Report.reporter_id], backref="reporter_user")
    reports_received = db.relationship("Report", foreign_keys=[Report.reported_user_id], backref="reported_user")
    chat_participants = db.relationship("ChatParticipant", backref="user", lazy=True)
    messages = db.relationship("Message", backref="sender", lazy=True)
    ai_history = db.relationship("AIHistory", backref="user", lazy=True)

    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "phone": self.phone,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": f"{self.first_name} {self.last_name}" if self.last_name else self.first_name,
            "dob": self.dob.isoformat() if self.dob else None,
            "gender": self.gender,
            "role": self.role,
            "class_level": self.class_level,
            "avatar": self.avatar,
            "bio": self.bio,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
# ------------------------------------------------
# UPDATED Authentication Routes for your schema
# ------------------------------------------------
# In your app.py - UPDATE THE REGISTER ROUTE
@app.route("/api/auth/register", methods=["POST"])
def register():
    """User registration with email/password"""
    try:
        data = request.get_json() or {}
        print("📝 Registration data received:", data)
        
        # Map frontend field names to backend field names
        # Frontend sends: user_type, student_class
        # Backend expects: role, class_level
        if 'user_type' in data:
            data['role'] = data.pop('user_type')
        if 'student_class' in data:
            data['class_level'] = data.pop('student_class')
        if 'date_of_birth' in data:
            data['dob'] = data.pop('date_of_birth')
        
        # Required fields based on your schema
        required_fields = ['username', 'first_name', 'dob', 'role', 'password', 'confirm_password']
        
        # Validate required fields
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"{field.replace('_', ' ').title()} is required"}), 400
        
        # Validate passwords match
        if data['password'] != data['confirm_password']:
            return jsonify({"error": "Passwords do not match"}), 400
        
        # Validate password strength
        if len(data['password']) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400
        
        # Validate email format if provided
        if data.get('email') and not validate_email(data['email']):
            return jsonify({"error": "Invalid email format"}), 400
        
        # Validate phone if provided
        if data.get('phone') and not validate_phone(data['phone']):
            return jsonify({"error": "Invalid phone number format"}), 400
        
        # Validate role
        if data['role'] not in ['student', 'teacher']:
            return jsonify({"error": "Role must be either 'student' or 'teacher'"}), 400
        
        # Validate gender (set default if not provided)
        if not data.get('gender'):
            data['gender'] = 'prefer_not_to_say'
        
        valid_genders = ['male', 'female', 'other', 'prefer_not_to_say']
        if data['gender'] not in valid_genders:
            return jsonify({"error": f"Gender must be one of: {', '.join(valid_genders)}"}), 400
        
        # Validate student class if user is student
        if data['role'] == 'student':
            if not data.get('class_level'):
                return jsonify({"error": "Class level is required for students"}), 400
            # Validate class level (6-12)
            try:
                class_level = int(data['class_level'])
                if class_level < 6 or class_level > 12:
                    return jsonify({"error": "Class level must be between 6 and 12"}), 400
            except ValueError:
                return jsonify({"error": "Class level must be a number between 6 and 12"}), 400
        else:
            # Teacher shouldn't have class level
            data['class_level'] = None
        
        # Check if username already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({"error": "Username already exists"}), 400
        
        # Check if email already exists (if provided)
        if data.get('email') and User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "Email already exists"}), 400
        
        # Check if phone already exists (if provided)
        if data.get('phone') and User.query.filter_by(phone=data['phone']).first():
            return jsonify({"error": "Phone number already exists"}), 400
        
        # Parse date of birth
        try:
            dob = datetime.strptime(data['dob'], '%Y-%m-%d').date()
            # Check if user is at least 13 years old
            age = (datetime.now().date() - dob).days // 365
            if age < 13:
                return jsonify({"error": "You must be at least 13 years old to register"}), 400
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
        
        # Hash password
        password_hash = hash_password(data['password'])
        
        # Create new user
        new_user = User(
            username=data['username'],
            email=data.get('email'),
            phone=data.get('phone'),
            first_name=data['first_name'],
            last_name=data.get('last_name'),
            dob=dob,
            gender=data['gender'],
            role=data['role'],
            class_level=data.get('class_level'),
            password_hash=password_hash
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Create JWT token
        token = create_access_token(
            identity=str(new_user.id), 
            expires_delta=timedelta(days=30)
        )
        
        print(f"✅ User registered successfully: {new_user.username}")
        
        return jsonify({
            "message": "Registration successful",
            "access_token": token,
            "user": new_user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Registration error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Registration failed. Please try again."}), 500

@app.route("/api/auth/login", methods=["POST"])
def login():
    """User login with email/phone/username and password"""
    try:
        data = request.get_json() or {}
        print("📝 Login attempt:", {k: v for k, v in data.items() if k != 'password'})
        
        identifier = data.get('identifier', '').strip()
        password = data.get('password', '')
        
        if not identifier or not password:
            return jsonify({"error": "Identifier and password are required"}), 400
        
        # Find user by email, phone, or username
        user = None
        
        # Try email first
        if validate_email(identifier):
            user = User.query.filter_by(email=identifier).first()
        
        # Try phone if not found by email
        if not user and validate_phone(identifier):
            user = User.query.filter_by(phone=identifier).first()
        
        # Try username if not found by email or phone
        if not user:
            user = User.query.filter_by(username=identifier).first()
        
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Verify password
        if not verify_password(password, user.password_hash):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Create JWT token
        token = create_access_token(
            identity=str(user.id), 
            expires_delta=timedelta(days=30)
        )
        
        print(f"✅ User logged in successfully: {user.username}")
        
        return jsonify({
            "message": "Login successful",
            "access_token": token,
            "user": user.to_dict()
        }), 200
        
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Login failed. Please try again."}), 500
    

@app.route("/api/auth/me", methods=["GET"])
@jwt_required()
def get_current_user():
    """Get current user profile"""
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({"user": user.to_dict()}), 200
        
    except Exception as e:
        print(f"❌ Get current user error: {str(e)}")
        return jsonify({"error": "Failed to get user profile"}), 500

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

# ------------------------------------------------
# KEEP ALL YOUR EXISTING ROUTES (Posts, Reels, Chats, etc.)
# ------------------------------------------------

@app.route("/api/ping")
def healthcheck():
    return jsonify({"ok": True, "status": "healthy", "time": datetime.utcnow().isoformat()}), 200

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
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f or f.filename == '':
        return jsonify({"error": "No file selected"}), 400

    # Check file extension
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
    file_ext = os.path.splitext(f.filename.lower())[1]
    if file_ext not in allowed_extensions:
        return jsonify({"error": "Only image files allowed (JPG, PNG, GIF, WebP)"}), 400

    try:
        print(f"📤 Uploading file: {f.filename}")
        
        # Reset file pointer and get file size
        f.seek(0, 2)  # Go to end
        file_size = f.tell()
        f.seek(0)  # Reset to beginning
        
        print(f"📁 File size: {file_size} bytes")
        
        if file_size > 10 * 1024 * 1024:  # 10MB limit
            return jsonify({"error": "File too large. Maximum size is 10MB"}), 400

        # SIMPLIFIED Cloudinary upload - remove complex transformations
        upload_result = cloudinary.uploader.upload(
            f,
            folder="sirverse",
            resource_type="auto"  # Let Cloudinary detect type automatically
        )
        
        print(f"✅ Upload successful: {upload_result.get('secure_url')}")
        
        return jsonify({
            "url": upload_result.get("secure_url"),
            "public_id": upload_result.get("public_id")
        }), 201
        
    except Exception as e:
        print(f"❌ Cloudinary upload failed: {str(e)}")
        
        # FALLBACK: Save file locally
        try:
            import uuid
            filename = f"{uuid.uuid4()}_{f.filename}"
            filepath = os.path.join("uploads", filename)
            
            # Create uploads directory if it doesn't exist
            os.makedirs("uploads", exist_ok=True)
            
            f.save(filepath)
            
            # For Railway, you might need to use a different approach for serving files
            # This creates a local URL that your frontend can access
            local_url = f"/uploads/{filename}"
            
            print(f"✅ File saved locally: {filename}")
            
            return jsonify({
                "url": local_url,
                "public_id": filename,
                "note": "File saved locally (Cloudinary failed)"
            }), 201
            
        except Exception as fallback_error:
            print(f"❌ Local fallback also failed: {str(fallback_error)}")
            return jsonify({"error": "Upload failed. Please try a different file or try again later."}), 500

@app.route("/api/upload/reel", methods=["POST"])
@jwt_required()
def upload_reel():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f or f.filename == '':
        return jsonify({"error": "No file selected"}), 400

    # Check video file extensions
    if not f.filename.lower().endswith((".mp4", ".mov", ".avi", ".webm", ".mkv")):
        return jsonify({"error": "Only video files allowed (MP4, MOV, AVI, WEBM, MKV)"}), 400

    try:
        print(f"🎬 Uploading reel: {f.filename}")
        
        # Get file size
        f.seek(0, 2)
        file_size = f.tell()
        f.seek(0)
        
        print(f"📁 Reel size: {file_size} bytes")
        
        if file_size > 50 * 1024 * 1024:  # 50MB limit for videos
            return jsonify({"error": "Video too large. Maximum size is 50MB"}), 400

        # SIMPLIFIED video upload
        upload_result = cloudinary.uploader.upload(
            f,
            folder="sirverse_reels",
            resource_type="video"
        )
        
        print(f"✅ Reel upload successful: {upload_result.get('secure_url')}")
        
        return jsonify({
            "url": upload_result.get("secure_url"),
            "public_id": upload_result.get("public_id"),
            "duration": upload_result.get("duration"),
            "format": upload_result.get("format")
        }), 201
        
    except Exception as e:
        print(f"❌ Reel upload failed: {str(e)}")
        
        # FALLBACK for reels
        try:
            import uuid
            filename = f"{uuid.uuid4()}_{f.filename}"
            filepath = os.path.join("uploads", filename)
            
            os.makedirs("uploads", exist_ok=True)
            f.save(filepath)
            
            local_url = f"/uploads/{filename}"
            
            print(f"✅ Reel saved locally: {filename}")
            
            return jsonify({
                "url": local_url,
                "public_id": filename,
                "note": "Reel saved locally (Cloudinary failed)"
            }), 201
            
        except Exception as fallback_error:
            print(f"❌ Reel fallback failed: {str(fallback_error)}")
            return jsonify({"error": "Reel upload failed. Please try a different video or try again later."}), 500

    

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
            "first_name": user.first_name,
            "last_name": user.last_name,
            "full_name": f"{user.first_name} {user.last_name}" if user.last_name else user.first_name,
            "avatar": user.avatar,
            "bio": user.bio,
            "role": user.role,
            "class_level": user.class_level,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "created_at_pk": to_pk_time(user.created_at)[0] if user.created_at else None,
            "created_at_pk_human": to_pk_time(user.created_at)[1] if user.created_at else None,
            "total_posts": len(posts),
            "total_reels": len(reels)
        },
        "posts": [post_dict(p) for p in posts],
        "reels": [reel_dict(r) for r in reels]
    }), 200

@app.route("/api/users/<int:uid>", methods=["PUT"])
@jwt_required()
def update_user(uid):
    try:
        current_user_id = int(get_jwt_identity())
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if current_user_id != uid:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json() or {}
    user = User.query.get_or_404(uid)

    if "first_name" in data:
        user.first_name = data.get("first_name") or None
    if "last_name" in data:
        user.last_name = data.get("last_name") or None
    if "bio" in data:
        user.bio = data.get("bio") or None
    if "avatar" in data:
        user.avatar = data.get("avatar") or user.avatar

    db.session.commit()

    return jsonify({
        "message": "Profile updated",
        "user": user.to_dict()
    }), 200

@app.route("/api/stats", methods=["GET"])
@jwt_required()
def get_user_stats():
    try:
        uid = int(get_jwt_identity())
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    posts_count = Post.query.filter_by(user_id=uid).count()
    reels_count = Reel.query.filter_by(user_id=uid).count()
    comments_count = Comment.query.filter_by(user_id=uid).count()

    user_posts = Post.query.filter_by(user_id=uid).all()
    post_ids = [p.id for p in user_posts]
    likes_received = Like.query.filter(Like.post_id.in_(post_ids)).count() if post_ids else 0

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

# Follow/Unfollow System
@app.route("/api/users/<int:user_id>/follow", methods=["POST"])
@jwt_required()
def follow_user(user_id):
    current_user_id = int(get_jwt_identity())
    
    if current_user_id == user_id:
        return jsonify({"error": "Cannot follow yourself"}), 400
    
    user_to_follow = User.query.get_or_404(user_id)
    
    existing_follow = Follow.query.filter_by(
        follower_id=current_user_id, 
        following_id=user_id
    ).first()
    
    if existing_follow:
        return jsonify({"error": "Already following this user"}), 400
    
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

# Block/Unblock System
@app.route("/api/users/<int:user_id>/block", methods=["POST"])
@jwt_required()
def block_user(user_id):
    current_user_id = int(get_jwt_identity())
    
    if current_user_id == user_id:
        return jsonify({"error": "Cannot block yourself"}), 400
    
    user_to_block = User.query.get_or_404(user_id)
    
    existing_block = Block.query.filter_by(
        blocker_id=current_user_id, 
        blocked_id=user_id
    ).first()
    
    if existing_block:
        return jsonify({"error": "User already blocked"}), 400
    
    Follow.query.filter_by(follower_id=current_user_id, following_id=user_id).delete()
    Follow.query.filter_by(follower_id=user_id, following_id=current_user_id).delete()
    
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

# Report System
@app.route("/api/report", methods=["POST"])
@jwt_required()
def create_report():
    current_user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    
    report_type = data.get("report_type")
    description = data.get("description", "").strip()
    reported_user_id = data.get("reported_user_id")
    reported_post_id = data.get("reported_post_id")
    reported_reel_id = data.get("reported_reel_id")
    
    if not report_type:
        return jsonify({"error": "Report type is required"}), 400
    
    if not any([reported_user_id, reported_post_id, reported_reel_id]):
        return jsonify({"error": "Must report a user, post, or reel"}), 400
    
    try:
        reported_user_id = int(reported_user_id) if reported_user_id else None
        reported_post_id = int(reported_post_id) if reported_post_id else None
        reported_reel_id = int(reported_reel_id) if reported_reel_id else None
    except (TypeError, ValueError) as e:
        return jsonify({"error": "Invalid ID format"}), 400
    
    if reported_user_id:
        user = User.query.get(reported_user_id)
        if not user:
            return jsonify({"error": "Reported user not found"}), 404
    
    if reported_post_id:
        post = Post.query.get(reported_post_id)
        if not post:
            return jsonify({"error": "Reported post not found"}), 404
    
    if reported_reel_id:
        reel = Reel.query.get(reported_reel_id)
        if not reel:
            return jsonify({"error": "Reported reel not found"}), 404
    
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
    
    query = Report.query.filter(
        Report.reporter_id == current_user_id,
        Report.report_type == report_type,
        Report.created_at >= twenty_four_hours_ago
    )
    
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
        return jsonify({"error": "You have already reported this content recently. Please wait 24 hours before reporting again."}), 400
    
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
        
        return jsonify({
            "message": "Report submitted successfully. Our team will review it shortly.",
            "report_id": report.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to create report"}), 500

@app.route("/api/report/types", methods=["GET"])
@jwt_required(optional=True)
def get_report_types():
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
    
    return jsonify({"report_types": report_types}), 200



@app.route("/delete-account")
def delete_account_page():
    return """
    <html>
      <head><title>Delete Account – SirVerse</title></head>
      <body>
        <h2>Delete Account Request</h2>
        <p>To delete your SirVerse account and all associated data, please email <strong>sirversegpt@gmail.com</strong> from the email address you used to register. We will process your request within 30 days.</p>
      </body>
    </html>
       """

# Chat System
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

    other = data.get("other_user_id")
    username = data.get("username")
    phone = data.get("phone")

    other_user = None
    if other:
        other_user = User.query.get(int(other))
    elif username:
        other_user = User.query.filter_by(username=username).first()
    elif phone:
        other_user = User.query.filter_by(phone=phone).first()

    if not other_user:
        return jsonify({"error": "User not found"}), 404

    existing = ChatRoom.query.filter_by(is_group=False).all()
    for r in existing:
        ids = [p.user_id for p in r.participants]
        if set(ids) == set([uid, other_user.id]):
            return jsonify({"room": room_dict(r, uid)}), 200

    r = ChatRoom(is_group=False)
    db.session.add(r)
    db.session.commit()

    db.session.add(ChatParticipant(room_id=r.id, user_id=uid))
    db.session.add(ChatParticipant(room_id=r.id, user_id=other_user.id))
    db.session.commit()

    return jsonify({"room": room_dict(r, uid)}), 201

# SocketIO handlers
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
        return False
    connected_users[sid] = uid
    emit("user_online", {"user_id": uid}, broadcast=True)
    print(f"✅ user {uid} connected via socket.")

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

    # 1️⃣ Create a temporary instant message (NO DB WAIT)
    temp_msg = {
        "id": -1,  # temporary
        "room_id": room,
        "sender": {"id": uid},
        "content": text,
        "created_at": datetime.utcnow().isoformat(),
        "created_at_pk": None,
        "created_at_pk_human": datetime.utcnow().strftime("%Y-%m-%d %I:%M %p")
    }

    # 2️⃣ Emit instantly → users see message immediately (0.01s)
    emit("receive_message", temp_msg, room=str(room))

    # 3️⃣ Save to DB in background (FAST + NON-BLOCKING)
    def save_message():
        msg = Message(room_id=room, sender_id=uid, content=text)
        db.session.add(msg)
        db.session.commit()
        
        # After saving, send the REAL message with correct ID + time
        emit("receive_message", message_dict(msg), room=str(room))

    # Run background saving
    eventlet.spawn(save_message)


# AI Assistant
import requests, time, hashlib

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama3-8b-instant")
HF_API_KEY = os.getenv("HF_API_KEY")
HF_MODEL = os.getenv("HF_MODEL", "meta-llama/Meta-Llama-3-8B-Instruct")

SIRG_CACHE = {}
CACHE_TTL = 3600

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
    
    # Define prefix for different modes
    prefix_map = {
        "explain": "Explain step by step and clearly:",
        "summarize": "Summarize this text as short study notes:",
        "quiz": "Create 5 multiple-choice questions with answers about:",
        "translate_urdu": "Translate the following into Urdu (simple words):",
    }
    
    prefix = prefix_map.get(mode, "Explain:")
    
    # FALLBACK RESPONSES - Always available even when AI is down
    fallback_responses = {
        "explain": f"**I'd be happy to explain '{prompt}'!** 🔍\n\nSince the AI service is temporarily being configured, here's what I suggest:\n\n• **Look up '{prompt}'** in your textbooks or course materials\n• **Ask your teacher** for clarification during class\n• **Search reliable educational websites** like Khan Academy or educational YouTube channels\n• **Discuss with classmates** to get different perspectives\n• **Break it down into smaller parts** and research each one\n\nThe AI feature will be fully operational soon! In the meantime, these traditional learning methods are very effective. 🎓",
        
        "summarize": f"**Let me help summarize '{prompt}'!** 📝\n\n**Key Areas to Focus On:**\n• **Main concepts and ideas** - What are the core principles?\n• **Important dates/events** - Any significant timeline?\n• **Key people/places** - Who or what is central to this topic?\n• **Cause and effect** - How do different elements relate?\n• **Key takeaways** - What's most important to remember?\n\n**Study Tip:** Create bullet points or mind maps for better retention! 🧠\n\nThe summarization feature is being upgraded and will return shortly with enhanced capabilities!",
        
        "quiz": f"**Great! Let me create a quiz about '{prompt}'!** 🎯\n\n**Sample Quiz Structure You Can Create:**\n\n**Multiple Choice (Create 3-5 questions):**\n1. What is the main concept of {prompt}?\n   A) [Option A]\n   B) [Option B] \n   C) [Option C]\n   D) [Option D]\n\n**True/False (Create 2-3 statements):**\n1. {prompt} involves complex calculations. (True/False)\n2. This topic is primarily theoretical. (True/False)\n\n**Short Answer (Create 1-2 questions):**\n1. Explain the significance of {prompt} in your own words.\n\n**Study Tip:** Creating your own quiz questions is an excellent learning strategy! 📚\n\nThe quiz generator is currently being enhanced with more question types and will be available soon!",
        
        "translate_urdu": f"**میں آپ کے سوال '{prompt}' کا ترجمہ کر سکتا ہوں!** 🌐\n\n**اردو ترجمہ کے لیے مفید مشورے:**\n• **واضح اور سادہ جملے** استعمال کریں\n• **مناسب اردو الفاظ** منتخب کریں\n• **گرامر کا خیال** رکھیں\n• **مقامی زبان** کے الفاظ شامل کریں\n\n**مثال کے طور پر:**\nاگر آپ کا سوال سائنس کے بارے میں ہے، تو 'Science' کا ترجمہ 'سائنس' کریں۔\n\n**ترجمہ کی سروس** جلد دستیاب ہوگی! اس وقت آپ درج ذیل طریقے استعمال کر سکتے ہیں:\n• **گوگل ٹرانسلیٹ** کا استعمال\n• **اردو لغت** سے مدد لیں\n• **اساتذہ سے پوچھیں**\n\nشکریہ! 🎉 انتظار کیجیے، یہ فیچر جلد ہی مکمل طور پر فعال ہو جائے گا۔"
    }
    
    # Try real AI first if API keys are available
    full_prompt = f"{prefix}\n\n{prompt}"
    cache_key = hashlib.sha256(full_prompt.encode()).hexdigest()
    
    # Check cache first
    cached = get_cache(cache_key)
    if cached:
        return jsonify({"reply": cached, "cached": True, "source": "cache"})

    # Try Groq AI
    if GROQ_API_KEY and GROQ_API_KEY != "your_groq_api_key_here":
        try:
            print(f"🤖 Trying Groq AI for: {prompt[:50]}...")
            reply = query_groq(full_prompt)
            set_cache(cache_key, reply)
            return jsonify({
                "reply": reply, 
                "source": "groq",
                "cached": False
            })
        except Exception as e:
            print(f"❌ Groq error: {str(e)}")

    # Try HuggingFace
    if HF_API_KEY and HF_API_KEY != "your_huggingface_api_key_here":
        try:
            print(f"🤖 Trying HuggingFace for: {prompt[:50]}...")
            reply = query_hf(full_prompt)
            set_cache(cache_key, reply)
            return jsonify({
                "reply": reply, 
                "source": "huggingface", 
                "cached": False
            })
        except Exception as e:
            print(f"❌ HuggingFace error: {str(e)}")

    # Use intelligent fallback response
    fallback_reply = fallback_responses.get(
        mode, 
        f"**I received your question about '{prompt}'!** 📚\n\n**The AI service is currently being set up and will be available soon.**\n\n**In the meantime, here are some helpful suggestions:**\n• **Research online** using educational resources\n• **Consult your textbooks** or course materials\n• **Ask your teacher or professor** for guidance\n• **Form a study group** with classmates\n• **Break down complex topics** into smaller, manageable parts\n\n**Learning Tip:** Sometimes the process of searching for answers yourself can lead to deeper understanding! 🌟\n\nThank you for your patience while we enhance this feature! 🚀"
    )
    
    print(f"📝 Using fallback response for mode: {mode}")
    
    return jsonify({
        "reply": fallback_reply, 
        "source": "fallback",
        "note": "AI service is being configured - educational suggestions provided",
        "cached": False
    })


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

    # SIMPLE + CLEAN FIX
    role = data.get("role") or data.get("sender")
    message = data.get("message") or data.get("text")

    msg = AIHistory(
        user_id=uid,
        role=role,
        message=message
    )

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

# Privacy Policy & Terms
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


# ============================
# 📦 CREATE ALL DATABASE TABLES
# ============================
with app.app_context():
    try:
        db.create_all()
        print("📦 All database tables created successfully.")
    except Exception as e:
        print("❌ Error creating tables:", e)

# ------------------------------------------------
# ✅ APP ENTRY POINT
# ------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"🚀 SirVerse GPT backend running on port {port}...")

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=False
    )

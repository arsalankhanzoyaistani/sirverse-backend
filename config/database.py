# backend/config/database.py

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from dotenv import load_dotenv
from pathlib import Path
import os

# ------------------------------------------------
# ✅ Load environment variables from .env (works local + Railway)
# ------------------------------------------------
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")

# ------------------------------------------------
# Database URL (fix 'postgres://' → 'postgresql+psycopg2://')
# ------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    elif DATABASE_URL.startswith("postgresql://"):
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
else:
    # Default fallback for local dev
    DATABASE_URL = "postgresql+psycopg2://sirverse_user:sirverse123@localhost:5432/sirverse_gpt_db"

# ------------------------------------------------
# Initialize SQLAlchemy instance
# ------------------------------------------------
db = SQLAlchemy()

def init_db(app):
    """Initialize the database connection for Flask app."""
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    print(f"🗄️ Database initialized: {DATABASE_URL}")

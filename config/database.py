import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

db = SQLAlchemy()

def init_db(app):
    # Get DATABASE_URL from environment
    db_url = os.getenv("DATABASE_URL")

    # ✅ Auto-fix prefix for psycopg3
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif db_url and db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

    # Apply to Flask config
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize SQLAlchemy
    db.init_app(app)

    # ✅ Test the connection (safe)
    try:
        engine = create_engine(db_url)
        with engine.connect() as conn:
            print("✅ Database connection successful (psycopg3)")
    except OperationalError as e:
        print("❌ Database connection failed:", e)
        print("⚠️ Check DATABASE_URL or Railway Postgres settings.")

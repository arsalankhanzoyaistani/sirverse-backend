# backend/config/database.py

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Get the database URL from .env
DATABASE_URL = os.getenv("DATABASE_URL")

# Initialize SQLAlchemy instance
db = SQLAlchemy()

def init_db(app):
    """Initialize the database connection for Flask app."""
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

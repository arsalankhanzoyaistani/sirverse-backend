# ✅ FIXED run_server.py
import eventlet
eventlet.monkey_patch()

import os
import sys
from app import app, socketio, db, create_default_legal_content

# Initialize database
with app.app_context():
    try:
        db.create_all()
        create_default_legal_content()
        print("✅ Database tables created successfully")
    except Exception as e:
        print(f"⚠️ Database initialization warning: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    
    print(f"🚀 Starting SirVerse backend on port {port}")
    print(f"📊 Database URL: {os.environ.get('DATABASE_URL', 'Not set')}")
    
    socketio.run(
        app, 
        host="0.0.0.0", 
        port=port, 
        debug=debug,
        log_output=True,
        allow_unsafe_werkzeug=True
    )
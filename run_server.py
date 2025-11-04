# backend/run_server.py
# ------------------------------------------------
# ✅ Permanent fix for Eventlet monkey_patch issue
# ------------------------------------------------
import os
import eventlet
eventlet.monkey_patch()

from app import app, socketio

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # ✅ Railway provides its own port
    print(f"🚀 SirVerse GPT backend running on port {port}...")
    socketio.run(app, host="0.0.0.0", port=port)

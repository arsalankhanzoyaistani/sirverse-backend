# ✅ backend/run_server.py
import os
import eventlet
eventlet.monkey_patch()

from app import app, socketio

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 SirVerse GPT backend running on port {port} (Eventlet mode)")
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)

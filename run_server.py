# backend/run_server.py
# ------------------------------------------------


# ==============================================
# 🚀 SirVerse GPT Backend — Stable Eventlet Setup
# ==============================================
import os
import eventlet
import eventlet.wsgi
eventlet.monkey_patch()

from app import app, socketio

if __name__ == "__main__":
    # ✅ Use Railway's provided port or fallback to 8080
    port = int(os.environ.get("PORT", 8080))

    # ✅ Small safety fix: print logs so Railway knows server started
    print(f"🚀 SirVerse GPT backend running with Eventlet & SocketIO on port {port}")

    # ✅ Run Flask-SocketIO with Eventlet WSGI server
    try:
        socketio.run(app, host="0.0.0.0", port=port)
    except Exception as e:
        print(f"❌ Server failed to start: {e}")

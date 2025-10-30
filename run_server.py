# backend/run_server.py
# ✅ Improved version (works on Railway + local)
import os
import eventlet
eventlet.monkey_patch(all=True)

from app import app, socketio

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 SirVerse GPT backend running on port {port} with Eventlet & SocketIO")
    socketio.run(app, host="0.0.0.0", port=port)

# backend/run_server.py
# ------------------------------------------------
# ✅ Permanent fix for Eventlet monkey_patch issue
# ------------------------------------------------
import eventlet
eventlet.monkey_patch(all=True)  # must be first!

from app import app, socketio  # import AFTER patching

if __name__ == "__main__":
    print("🚀 SirVerse GPT backend running with Eventlet & SocketIO")
    socketio.run(app, host="0.0.0.0", port=5000)

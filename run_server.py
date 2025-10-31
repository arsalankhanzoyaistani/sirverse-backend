# backend/run_server.py
# ✅ Permanent fix — works on Railway (Python 3.13) and locally without Eventlet

import os
from app import app, socketio

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 SirVerse GPT backend running on port {port} using THREADING mode (permanent fix)")
    socketio.run(app, host="0.0.0.0", port=port)

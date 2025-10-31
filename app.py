import eventlet
eventlet.monkey_patch(all=True)

import os
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

@app.route('/ping')
def ping():
    return jsonify({"ok": True, "message": "Backend is working!"})

@app.route('/api/posts')
def test_posts():
    return jsonify({"posts": [], "message": "API is working"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Simple test backend starting on port {port}")
    
    from flask_socketio import SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*")
    socketio.run(app, host="0.0.0.0", port=port)
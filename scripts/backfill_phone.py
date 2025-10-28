import sys, os
# 🔧 make sure Python knows where your backend root is
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, db, User  # now it will find app.py

with app.app_context():
    users = User.query.filter((User.phone == None) | (User.phone == "")).all()
    print("📱  Backfilling", len(users), "users with placeholder phone numbers...")
    for u in users:
        u.phone = f"+000{u.id:06d}"     # e.g. +000000123
        u.otp_hash = None
        u.otp_expiry = None
        u.otp_attempts = 0
        db.session.add(u)
    db.session.commit()
    print("✅  Done backfilling all users.")


import os
import re
import sqlite3
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
DB = os.path.join(BASE_DIR, "users.db")

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "login.html")


@app.post("/api/signup")
def signup():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not EMAIL_RE.match(email):
        return jsonify(ok=False, error="Iltimos, yaroqli email kiriting."), 400
    if not USERNAME_RE.match(username):
        return jsonify(ok=False, error="Username: 3-20 ta belgi (harflar, raqamlar, _)."), 400
    if len(password) < 6:
        return jsonify(ok=False, error="Parol kamida 6 ta belgidan iborat bo'lishi kerak."), 400

    with get_db() as db:
        if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            return jsonify(ok=False, error="Bu email allaqachon ro'yxatdan o'tgan."), 409
        if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            return jsonify(ok=False, error="Bu username band qilingan."), 409

        try:
            db.execute(
                "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                (email, username, generate_password_hash(password)),
            )
        except sqlite3.IntegrityError:
            return jsonify(ok=False, error="Email yoki username allaqachon mavjud."), 409

    return jsonify(ok=True, message="Muvaffaqiyatli ro'yxatdan o'tdingiz!"), 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify(ok=False, error="Noto'g'ri username yoki parol."), 401

    return jsonify(ok=True, message="Muvaffaqiyatli kirdingiz!"), 200


@app.get("/dashboard")
def dashboard():
    return send_from_directory(app.static_folder, "dashboard.html")


# Admin panel uchun API'lar
@app.get("/api/admin/users")
def admin_get_users():
    with get_db() as db:
        users = db.execute("SELECT id, email, username, created_at FROM users").fetchall()
        return jsonify([dict(u) for u in users]), 200


@app.delete("/api/admin/users/<int:user_id>")
def admin_delete_user(user_id):
    with get_db() as db:
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
    return jsonify(ok=True, message="Foydalanuvchi o'chirildi."), 200


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
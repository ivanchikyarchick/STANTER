import os
import sqlite3
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, g, jsonify, request, send_file, session
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "stanter.db")
FRONTEND = os.path.join(os.path.dirname(BASE_DIR), "index.html")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "change-this-secret-before-deploy"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    connection = sqlite3.connect(DATABASE)
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            share_stats INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS stunts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            client_id TEXT,
            happened_at TEXT NOT NULL,
            duration REAL NOT NULL,
            distance REAL NOT NULL,
            avg_speed REAL NOT NULL,
            max_tilt REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, client_id)
        );
    """)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
    additions = {
        "telegram_id": "INTEGER", "telegram_username": "TEXT",
        "first_name": "TEXT", "photo_url": "TEXT", "last_active": "TEXT"
    }
    for name, sql_type in additions.items():
        if name not in columns:
            connection.execute(f"ALTER TABLE users ADD COLUMN {name} {sql_type}")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_telegram_id ON users(telegram_id) WHERE telegram_id IS NOT NULL")
    connection.commit()
    connection.close()


def body():
    return request.get_json(silent=True) or {}


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db().execute(
        "SELECT id, username, email, share_stats, created_at, telegram_id, telegram_username, first_name, photo_url FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify(error="Спочатку увійдіть в акаунт"), 401
        return view(*args, **kwargs)
    return wrapped


def user_json(user):
    return {
        "id": user["id"], "username": user["username"], "email": user["email"],
        "shareStats": bool(user["share_stats"]), "createdAt": user["created_at"],
        "telegramId": user["telegram_id"], "telegramUsername": user["telegram_username"],
        "firstName": user["first_name"], "photoUrl": user["photo_url"],
    }


def validate_telegram_init_data(raw_data):
    """Validate Telegram Mini App initData according to Telegram's HMAC scheme."""
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not bot_token or not raw_data:
        return None
    values = dict(parse_qsl(raw_data, keep_blank_values=True))
    received_hash = values.pop("hash", "")
    if not received_hash:
        return None
    check_string = "\n".join(f"{key}={values[key]}" for key in sorted(values))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    expected_hash = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    try:
        auth_date = int(values.get("auth_date", "0"))
    except ValueError:
        return None
    if not hmac.compare_digest(expected_hash, received_hash) or abs(time.time() - auth_date) > 86400:
        return None
    try:
        return json.loads(values.get("user", "{}"))
    except json.JSONDecodeError:
        return None


def login_telegram_user(tg_user):
    telegram_id = int(tg_user["id"])
    tg_username = str(tg_user.get("username") or "").strip()[:64] or None
    first_name = str(tg_user.get("first_name") or "Rider").strip()[:64]
    photo_url = str(tg_user.get("photo_url") or "")[:500] or None
    user = db().execute("SELECT id FROM users WHERE telegram_id = ?", (telegram_id,)).fetchone()
    now = datetime.now(timezone.utc).isoformat()
    if user:
        db().execute("UPDATE users SET telegram_username=?, first_name=?, photo_url=?, last_active=? WHERE id=?",
                     (tg_username, first_name, photo_url, now, user["id"]))
        user_id = user["id"]
    else:
        base = tg_username or f"rider_{telegram_id}"
        username = base
        suffix = 1
        while db().execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            suffix += 1
            username = f"{base[:24]}_{suffix}"
        cur = db().execute("""INSERT INTO users
            (username,email,password_hash,created_at,telegram_id,telegram_username,first_name,photo_url,last_active)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (username, f"tg-{telegram_id}@stanter.local", "telegram-only", now, telegram_id, tg_username, first_name, photo_url, now))
        user_id = cur.lastrowid
    db().commit()
    session.clear()
    session["user_id"] = user_id
    return current_user()


@app.get("/")
def index():
    return send_file(FRONTEND)


@app.get("/api/config")
def public_config():
    return jsonify(testMode=os.environ.get("TEST_MODE", "").lower() in {"1", "true", "yes", "on"})


@app.post("/api/register")
def register():
    data = body()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if len(username) < 3 or len(username) > 30:
        return jsonify(error="Ім’я має містити від 3 до 30 символів"), 400
    if "@" not in email or len(email) > 120:
        return jsonify(error="Вкажіть коректний email"), 400
    if len(password) < 8:
        return jsonify(error="Пароль має містити щонайменше 8 символів"), 400
    try:
        cur = db().execute(
            "INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
            (username, email, generate_password_hash(password), datetime.now(timezone.utc).isoformat()),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Таке ім’я або email уже використовується"), 409
    session.clear()
    session["user_id"] = cur.lastrowid
    return jsonify(user=user_json(current_user())), 201


@app.post("/api/telegram-auth")
def telegram_auth():
    tg_user = validate_telegram_init_data(str(body().get("initData", "")))
    if not tg_user or "id" not in tg_user:
        return jsonify(error="Не вдалося підтвердити Telegram-профіль"), 401
    return jsonify(user=user_json(login_telegram_user(tg_user)))


@app.post("/api/test-auth")
def test_auth():
    if os.environ.get("TEST_MODE", "").lower() not in {"1", "true", "yes", "on"}:
        return jsonify(error="Тестовий режим вимкнений"), 404
    test_id = int(os.environ.get("TEST_TELEGRAM_ID", "999000001"))
    test_user = {
        "id": test_id,
        "first_name": os.environ.get("TEST_USER_NAME", "Test Rider"),
        "username": os.environ.get("TEST_USER_USERNAME", "stanter_test_rider"),
        "photo_url": "",
    }
    return jsonify(user=user_json(login_telegram_user(test_user)))


@app.post("/api/login")
def login():
    data = body()
    login_value = str(data.get("login", "")).strip()
    user = db().execute("SELECT * FROM users WHERE username = ? OR email = ?", (login_value, login_value)).fetchone()
    if not user or not check_password_hash(user["password_hash"], str(data.get("password", ""))):
        return jsonify(error="Невірний логін або пароль"), 401
    session.clear()
    session["user_id"] = user["id"]
    return jsonify(user=user_json(current_user()))


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    user = current_user()
    return jsonify(user=user_json(user) if user else None)


@app.patch("/api/me/privacy")
@login_required
def privacy():
    share = bool(body().get("shareStats"))
    db().execute("UPDATE users SET share_stats = ? WHERE id = ?", (int(share), session["user_id"]))
    db().commit()
    return jsonify(user=user_json(current_user()))


@app.post("/api/stunts")
@login_required
def add_stunt():
    data = body()
    try:
        duration = max(0, float(data.get("duration", 0)))
        distance = max(0, float(data.get("distance", 0)))
        speed = max(0, float(data.get("avgSpeed", 0)))
        tilts = data.get("tiltData") or []
        max_tilt = max((abs(float(value)) for value in tilts), default=0)
    except (TypeError, ValueError):
        return jsonify(error="Некоректні дані станту"), 400
    if duration > 86400 or distance > 100000 or speed > 300 or max_tilt > 360:
        return jsonify(error="Значення станту виходять за допустимі межі"), 400
    happened_at = str(data.get("date") or datetime.now(timezone.utc).isoformat())[:40]
    client_id = str(data.get("clientId") or "")[:100] or None
    db().execute(
        "INSERT OR IGNORE INTO stunts(user_id,client_id,happened_at,duration,distance,avg_speed,max_tilt,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (session["user_id"], client_id, happened_at, duration, distance, speed, max_tilt, datetime.now(timezone.utc).isoformat()),
    )
    db().commit()
    return jsonify(ok=True), 201


@app.get("/api/my-stats")
@login_required
def my_stats():
    row = db().execute("""
        SELECT COUNT(*) count, COALESCE(SUM(distance),0) total_distance,
               COALESCE(MAX(distance),0) best_distance, COALESCE(MAX(avg_speed),0) best_speed
        FROM stunts WHERE user_id = ?
    """, (session["user_id"],)).fetchone()
    days = [r[0][:10] for r in db().execute(
        "SELECT DISTINCT happened_at FROM stunts WHERE user_id=? ORDER BY happened_at DESC", (session["user_id"],)
    ).fetchall()]
    streak = 0
    if days:
        from datetime import date
        parsed = sorted({date.fromisoformat(day) for day in days}, reverse=True)
        cursor = parsed[0]
        for day in parsed:
            if day == cursor:
                streak += 1
                cursor -= timedelta(days=1)
            elif day < cursor:
                break
    stats = dict(row)
    stats["streak"] = streak
    stats["achievements"] = [
        {"icon": "⚡", "name": "Перший стант", "unlocked": stats["count"] >= 1},
        {"icon": "🔥", "name": "Серія 3 дні", "unlocked": streak >= 3},
        {"icon": "🚀", "name": "Швидкість 20+", "unlocked": stats["best_speed"] >= 20},
        {"icon": "🏆", "name": "Дистанція 100 м", "unlocked": stats["total_distance"] >= 100},
    ]
    return jsonify(stats=stats)


@app.get("/api/community")
def community():
    rows = db().execute("""
        SELECT u.username, u.first_name, u.telegram_username, u.photo_url, COUNT(s.id) stunt_count,
               ROUND(COALESCE(SUM(s.distance),0),1) total_distance,
               ROUND(COALESCE(MAX(s.distance),0),1) best_distance,
               ROUND(COALESCE(MAX(s.avg_speed),0),1) best_speed
        FROM users u LEFT JOIN stunts s ON s.user_id = u.id
        WHERE u.share_stats = 1 GROUP BY u.id ORDER BY best_distance DESC, stunt_count DESC LIMIT 100
    """).fetchall()
    return jsonify(users=[dict(row) for row in rows])


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5055)), debug=os.environ.get("FLASK_DEBUG") == "1")

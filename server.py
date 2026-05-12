import os
import hashlib
import secrets
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__, static_folder='.')
CORS(app)

# ── Database connection ──────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(os.environ['DATABASE_URL'], sslmode='require')
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            guardian_pin TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS user_blocks (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            block_type TEXT NOT NULL,
            custom_word TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{hashed}"

def check_password(password, stored):
    salt, hashed = stored.split(':')
    return hashlib.sha256((password + salt).encode()).hexdigest() == hashed

# ── Serve HTML pages ─────────────────────────────────────────────
@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/app')
def apppage():
    return send_from_directory('.', 'app.html')

# ── API: Sign Up ─────────────────────────────────────────────────
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    pin = data.get('guardian_pin', '')

    if not name or not email or not password:
        return jsonify({'error': 'Please fill in all fields'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "INSERT INTO users (name, email, password_hash, guardian_pin) VALUES (%s, %s, %s, %s) RETURNING id, name",
            (name, email, hash_password(password), pin if pin else None)
        )
        user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'user_id': user['id'], 'name': user['name']})
    except psycopg2.errors.UniqueViolation:
        return jsonify({'error': 'This email is already registered'}), 400
    except Exception as e:
        return jsonify({'error': 'Something went wrong. Try again.'}), 500

# ── API: Login ───────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user or not check_password(password, user['password_hash']):
            return jsonify({'error': 'Wrong email or password'}), 401

        return jsonify({
            'success': True,
            'user_id': user['id'],
            'name': user['name'],
            'has_pin': bool(user['guardian_pin'])
        })
    except Exception as e:
        return jsonify({'error': 'Something went wrong. Try again.'}), 500

# ── API: Save block settings ─────────────────────────────────────
@app.route('/api/blocks', methods=['POST'])
def save_blocks():
    data = request.json
    user_id = data.get('user_id')
    blocks = data.get('blocks', [])       # e.g. ['adult', 'gambling']
    custom_words = data.get('custom_words', [])

    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    try:
        conn = get_db()
        cur = conn.cursor()
        # Clear old blocks first
        cur.execute("DELETE FROM user_blocks WHERE user_id = %s", (user_id,))
        # Save new ones
        for block in blocks:
            cur.execute(
                "INSERT INTO user_blocks (user_id, block_type) VALUES (%s, %s)",
                (user_id, block)
            )
        for word in custom_words:
            cur.execute(
                "INSERT INTO user_blocks (user_id, block_type, custom_word) VALUES (%s, %s, %s)",
                (user_id, 'custom', word.lower())
            )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': 'Could not save. Try again.'}), 500

# ── API: Get user blocks ─────────────────────────────────────────
@app.route('/api/blocks/<int:user_id>', methods=['GET'])
def get_blocks(user_id):
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT block_type, custom_word FROM user_blocks WHERE user_id = %s", (user_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'blocks': rows})
    except Exception as e:
        return jsonify({'error': 'Could not load blocks'}), 500

# ── API: Verify Guardian PIN ─────────────────────────────────────
@app.route('/api/verify-pin', methods=['POST'])
def verify_pin():
    data = request.json
    user_id = data.get('user_id')
    pin = data.get('pin', '')

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT guardian_pin FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user['guardian_pin'] and user['guardian_pin'] != pin:
            return jsonify({'success': False, 'error': 'Wrong PIN'}), 403

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': 'Something went wrong'}), 500

# ── Start ────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

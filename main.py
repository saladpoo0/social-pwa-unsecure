import os
import sys
import sqlite3
import subprocess
from flask import Flask, render_template, request, redirect, session
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
import user_management as db

# ── Auto-bootstrap the database on every startup ──────────────────────────────
# This ensures students never see "no such table" even if setup_db.py
# was never manually run, or if the .db file is missing / corrupted.
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "database_files", "database.db")
SETUP_SCRIPT = os.path.join(BASE_DIR, "database_files", "setup_db.py")

def _tables_exist():
    """Return True if the required tables are all present."""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        tables = {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        con.close()
        return {"users", "posts", "messages"}.issubset(tables)
    except Exception:
        return False

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "database_files"), exist_ok=True)
    if not os.path.exists(DB_PATH) or not _tables_exist():
        print("[SocialPWA] Setting up database...")
        result = subprocess.run(
            [sys.executable, SETUP_SCRIPT],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print("[SocialPWA] WARNING: setup_db failed:", result.stderr)
    else:
        print("[SocialPWA] Database already exists — skipping setup.")

init_db()

# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

# VULNERABILITY: Wildcard CORS — allows ANY origin to make credentialed requests
CORS(app)

# VULNERABILITY: Hardcoded secret key — session cookies can be forged
app.secret_key = "supersecretkey123"

# Enable CSRF protection
csrf = CSRFProtect(app)


# ── Home / Login ──────────────────────────────────────────────────────────────

@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
    # VULNERABILITY: Open Redirect — blindly follows 'url' query parameter
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    # VULNERABILITY: Reflected XSS — 'msg' rendered with |safe in template
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("index.html", msg=msg)

    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = db.retrieveUsers(username, password)
        if isLoggedIn:
            session['username'] = username  # Store username in session
            posts = db.getPosts()
            return render_template("feed.html", username=username, state=isLoggedIn, posts=posts)
        else:
            return render_template("index.html", msg="Invalid credentials. Please try again.")


# ── Sign Up ───────────────────────────────────────────────────────────────────

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB      = request.form["dob"]
        bio      = request.form.get("bio", "")
        # VULNERABILITY: No duplicate username check
        # VULNERABILITY: No input validation or password strength enforcement
        db.insertUser(username, password, DoB, bio)
        return render_template("index.html", msg="Account created! Please log in.")
    else:
        return render_template("signup.html")


# ── Social Feed ───────────────────────────────────────────────────────────────

@app.route("/feed.html", methods=["POST", "GET"])
def feed():
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        # FIX: Get username from session (trusted), not form data (user-controlled)
        username = session.get('username', None)
        if not username:
            return redirect("/", code=302)  # Redirect to login if not authenticated
        post_content = request.form["content"]
        db.insertPost(username, post_content)
        posts = db.getPosts()
        return render_template("feed.html", username=username, state=True, posts=posts)
    else:
        username = session.get('username', "Guest")
        posts = db.getPosts()
        return render_template("feed.html", username=username, state=True, posts=posts)


# ── User Profile ──────────────────────────────────────────────────────────────

@app.route("/profile")
def profile():
    # VULNERABILITY: No authentication check — any visitor can read any profile
    # VULNERABILITY: SQL Injection via 'user' parameter in getUserProfile()
    if request.args.get("url"):
        return redirect(request.args.get("url"), code=302)
    username = request.args.get("user", "")
    profile_data = db.getUserProfile(username)
    return render_template("profile.html", profile=profile_data, username=username)


# ── Direct Messages ───────────────────────────────────────────────────────────

@app.route("/messages", methods=["POST", "GET"])
def messages():
    # FIX: Check if user is authenticated
    username = session.get('username', None)
    if not username:
        return redirect("/", code=302)  # Redirect to login if not authenticated
    
    if request.method == "POST":
        # FIX: Get sender from session (trusted), not form data (user-controlled)
        recipient = request.form.get("recipient", "")
        body      = request.form.get("body", "")
        db.sendMessage(username, recipient, body)  # Use session username as sender
        msgs = db.getMessages(username)  # Only get messages for current user
        return render_template("messages.html", messages=msgs, username=username, recipient=recipient)
    else:
        # FIX: Only allow users to view their own inbox (no ?user= parameter exploitation)
        msgs = db.getMessages(username)
        return render_template("messages.html", messages=msgs, username=username, recipient=username)


# ── Success Page ──────────────────────────────────────────────────────────────

@app.route("/success.html")
def success():
    msg = request.args.get("msg", "Your action was completed successfully.")
    return render_template("success.html", msg=msg)


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)

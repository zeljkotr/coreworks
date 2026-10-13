import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

from dotenv_loader import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from flask import (
    Flask, abort, flash, g, redirect, render_template, request,
    session, url_for,
)
from werkzeug.security import check_password_hash


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("COREWORKS_SECRET_KEY"),
        DATABASE=os.environ.get(
            "COREWORKS_DATABASE",
            str(Path(app.instance_path) / "coreworks.sqlite3"),
        ),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get(
            "COREWORKS_COOKIE_SECURE", "0"
        ) == "1",
        PERMANENT_SESSION_LIFETIME=3600,
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "COREWORKS_SECRET_KEY is required. Configure it in .env."
        )

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
                    CHECK(role IN ('admin', 'user')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)
        db.commit()

    with app.app_context():
        init_db()

    def csrf_token():
        token = session.get("_csrf_token")
        if token is None:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def protect_post_requests():
        if request.method == "POST":
            expected = session.get("_csrf_token")
            supplied = request.form.get("_csrf_token", "")
            if not expected or not secrets.compare_digest(expected, supplied):
                abort(400, description="Invalid or missing CSRF token.")

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    def admin_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if session.get("role") != "admin":
                abort(403)
            return view(*args, **kwargs)
        return wrapped

    @app.context_processor
    def inject_user():
        return {
            "current_username": session.get("username"),
            "current_role": session.get("role"),
        }

    @app.get("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute(
                "SELECT id, username, password_hash, role "
                "FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session.permanent = True
                flash("Uspešno ste se prijavili.", "success")
                destination = request.args.get("next", "")
                if destination.startswith("/") and not destination.startswith("//"):
                    return redirect(destination)
                return redirect(url_for("dashboard"))

            flash("Neispravno korisničko ime ili lozinka.", "error")

        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        flash("Uspešno ste se odjavili.", "success")
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/monitor")
    @login_required
    def monitor():
        return redirect(url_for("monitor_status"))

    @app.get("/monitor/status")
    @login_required
    def monitor_status():
        return render_template("monitor.html")

    @app.get("/admin")
    @admin_required
    def admin():
        users = get_db().execute(
            "SELECT id, username, role, created_at FROM users ORDER BY id"
        ).fetchall()
        return render_template("admin.html", users=users)

    return app

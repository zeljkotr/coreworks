import tempfile
import unittest
from pathlib import Path

from werkzeug.security import generate_password_hash

from coreworks.hub import create_app


class HubTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        db_path = str(Path(self.temp.name) / "test.sqlite3")
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-secret-key-that-is-not-used-in-production",
            "DATABASE": db_path,
        })
        self.client = self.app.test_client()
        with self.app.app_context():
            from flask import current_app
            import sqlite3
            db = sqlite3.connect(current_app.config["DATABASE"])
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", generate_password_hash("correct horse battery staple"), "admin"),
            )
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("regular", generate_password_hash("regular test password"), "user"),
            )
            db.commit()
            db.close()

    def tearDown(self):
        self.temp.cleanup()

    def post_form(self, path, data):
        page = self.client.get(path)
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]
        return self.client.post(path, data={**data, "_csrf_token": token})

    def test_dashboard_requires_login(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_login_success(self):
        response = self.post_form("/login", {
            "username": "admin",
            "password": "correct horse battery staple",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/dashboard")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_login_failure(self):
        response = self.post_form("/login", {
            "username": "admin", "password": "wrong",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("Neispravno", response.get_data(as_text=True))

    def test_csrf_required(self):
        response = self.client.post("/login", data={
            "username": "admin", "password": "correct horse battery staple",
        })
        self.assertEqual(response.status_code, 400)

    def test_user_cannot_open_admin_page(self):
        self.post_form("/login", {
            "username": "regular", "password": "regular test password",
        })
        self.assertEqual(self.client.get("/admin").status_code, 403)

    def test_logout(self):
        self.post_form("/login", {
            "username": "admin",
            "password": "correct horse battery staple",
        })
        # Fetch a page while authenticated so the session has a CSRF token.
        self.client.get("/dashboard")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]

        response = self.client.post(
            "/logout",
            data={"_csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)


if __name__ == "__main__":
    unittest.main()

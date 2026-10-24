import os
import unittest
import tempfile
import sqlite3
from io import BytesIO
from werkzeug.security import generate_password_hash

# Set test environment
os.environ["SECRET_KEY"] = "test-secret-key-32-chars-long-12345"

from app import app, init_db, db, run, one, now

class TrustVaultSecurityTests(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

        with self.app.app_context():
            # Setup fresh test users
            run("DELETE FROM users WHERE email LIKE '%@test.local'")
            run("DELETE FROM documents WHERE title LIKE 'TestDoc%'")
            run("DELETE FROM logs WHERE user_name LIKE 'Test%'")
            
            # Create test users
            run("INSERT INTO users(name, email, password, role, created_at) VALUES(?,?,?,?,?)",
                ("Test Admin", "admin@test.local", generate_password_hash("AdminPass123!"), "admin", now()))
            self.admin_id = one("SELECT id FROM users WHERE email='admin@test.local'")["id"]

            run("INSERT INTO users(name, email, password, role, created_at) VALUES(?,?,?,?,?)",
                ("Test Owner", "owner@test.local", generate_password_hash("OwnerPass123!"), "owner", now()))
            self.owner_id = one("SELECT id FROM users WHERE email='owner@test.local'")["id"]

            run("INSERT INTO users(name, email, password, role, created_at) VALUES(?,?,?,?,?)",
                ("Test Viewer", "viewer@test.local", generate_password_hash("ViewerPass123!"), "viewer", now()))
            self.viewer_id = one("SELECT id FROM users WHERE email='viewer@test.local'")["id"]

            run("INSERT INTO users(name, email, password, role, created_at) VALUES(?,?,?,?,?)",
                ("Test Stranger", "stranger@test.local", generate_password_hash("StrangerPass123!"), "owner", now()))
            self.stranger_id = one("SELECT id FROM users WHERE email='stranger@test.local'")["id"]

            # Create an owner document
            cur = run("INSERT INTO documents(title, filename, stored_name, category, size, owner_id, created_at, updated_at) "
                      "VALUES(?,?,?,?,?,?,?,?)",
                      ("TestDoc Secure", "test.txt", "dummy_stored.txt", "Legal", 100, self.owner_id, now(), now()))
            self.doc_id = cur.lastrowid

    def login(self, email, password):
        return self.client.post("/login", data={"email": email, "password": password, "_csrf": ""}, follow_redirects=True)

    def login_user(self, user_id):
        with self.client.session_transaction() as sess:
            sess["uid"] = user_id
            sess["csrf"] = "dummy_csrf_token"

    # 1. Unauthenticated access redirect
    def test_unauthenticated_redirect(self):
        res = self.client.get("/documents")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])

    # 2. Viewer cannot access upload endpoint (403 Forbidden)
    def test_viewer_cannot_upload(self):
        self.login_user(self.viewer_id)
        res = self.client.get("/upload")
        self.assertEqual(res.status_code, 403)

    # 3. Viewer cannot view document without granted access (403 Forbidden)
    def test_viewer_cannot_access_unshared_doc(self):
        self.login_user(self.viewer_id)
        res = self.client.get(f"/doc/{self.doc_id}")
        self.assertEqual(res.status_code, 403)

    # 4. Unauthorized non-owner / stranger cannot grant or revoke document access
    def test_stranger_cannot_manage_access(self):
        self.login_user(self.stranger_id)
        res = self.client.post(f"/doc/{self.doc_id}/share", data={
            "user_id": str(self.viewer_id),
            "permission": "read",
            "_csrf": "dummy_csrf_token"
        })
        self.assertEqual(res.status_code, 403)

        # Stranger cannot revoke access
        res2 = self.client.post(f"/doc/{self.doc_id}/revoke/{self.viewer_id}", data={
            "_csrf": "dummy_csrf_token"
        })
        self.assertEqual(res2.status_code, 403)

    # 5. Viewer with granted 'edit' is capped to 'read' access
    def test_viewer_edit_role_capping(self):
        with self.app.app_context():
            run("INSERT OR REPLACE INTO shares(doc_id, user_id, permission, granted_at) VALUES(?,?,?,?)",
                (self.doc_id, self.viewer_id, "edit", now()))

        self.login_user(self.viewer_id)
        # Should be able to view doc
        res = self.client.get(f"/doc/{self.doc_id}")
        self.assertEqual(res.status_code, 200)

        # But trying to update/edit should fail with 403
        res_edit = self.client.post(f"/doc/{self.doc_id}/update", data={
            "title": "Hacked Title",
            "_csrf": "dummy_csrf_token"
        })
        self.assertEqual(res_edit.status_code, 403)

    # 6. Document Owner can manage sharing
    def test_owner_can_share_and_revoke(self):
        self.login_user(self.owner_id)
        # Share with viewer
        res = self.client.post(f"/doc/{self.doc_id}/share", data={
            "user_id": str(self.viewer_id),
            "permission": "read",
            "_csrf": "dummy_csrf_token"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        with self.app.app_context():
            share = one("SELECT * FROM shares WHERE doc_id=? AND user_id=?", (self.doc_id, self.viewer_id))
            self.assertIsNotNone(share)
            self.assertEqual(share["permission"], "read")

        # Revoke access
        res_revoke = self.client.post(f"/doc/{self.doc_id}/revoke/{self.viewer_id}", data={
            "_csrf": "dummy_csrf_token"
        }, follow_redirects=True)
        self.assertEqual(res_revoke.status_code, 200)

        with self.app.app_context():
            share_after = one("SELECT * FROM shares WHERE doc_id=? AND user_id=?", (self.doc_id, self.viewer_id))
            self.assertIsNone(share_after)

    # 7. Non-admin cannot access admin dashboard or audit logs
    def test_non_admin_cannot_view_admin_routes(self):
        self.login_user(self.owner_id)
        res_dash = self.client.get("/dashboard")
        self.assertEqual(res_dash.status_code, 403)

        res_logs = self.client.get("/logs")
        self.assertEqual(res_logs.status_code, 403)

        res_users = self.client.get("/users")
        self.assertEqual(res_users.status_code, 403)

    # 8. CSRF Protection: POST without matching CSRF token is rejected with 400
    def test_csrf_mismatch_rejected(self):
        with self.client.session_transaction() as sess:
            sess["uid"] = self.owner_id
            sess["csrf"] = "real_valid_csrf_token"

        res = self.client.post(f"/doc/{self.doc_id}/update", data={
            "title": "CSRF Attack Attempt",
            "_csrf": "attacker_fake_token"
        })
        self.assertEqual(res.status_code, 400)

    # 9. Access violations are recorded in Audit Logs
    def test_unauthorized_access_logged(self):
        self.login_user(self.stranger_id)
        # Attempt to access owner's document
        self.client.get(f"/doc/{self.doc_id}")

        with self.app.app_context():
            log_entry = one("SELECT * FROM logs WHERE action='access_denied' ORDER BY id DESC LIMIT 1")
            self.assertIsNotNone(log_entry)
            self.assertIn(f"doc #{self.doc_id}", log_entry["detail"])

if __name__ == "__main__":
    unittest.main()

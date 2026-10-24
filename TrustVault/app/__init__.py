import os, sqlite3, uuid, secrets, functools
from datetime import datetime
from flask import (Flask, g, render_template, request, redirect, url_for,
                   session, flash, abort, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INST = os.path.join(BASE, "instance")
UPLOADS = os.path.join(INST, "uploads")
AVATARS = os.path.join(INST, "avatars")
DB_PATH = os.path.join(INST, "trustvault.db")
for p in (UPLOADS, AVATARS):
    os.makedirs(p, exist_ok=True)

CATEGORIES = ["Identity", "Financial", "Legal", "Medical", "Education", "Property", "Work", "Other"]
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "png", "jpg", "jpeg", "zip"}
IMG_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
RANK = {"read": 1, "edit": 2, "owner": 3, "admin": 4}

def _secret():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = os.path.join(INST, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    return open(path).read().strip()

app = Flask(__name__)
app.config.update(SECRET_KEY=_secret(), MAX_CONTENT_LENGTH=16 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'owner', avatar TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS documents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, filename TEXT NOT NULL,
  stored_name TEXT NOT NULL, category TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0,
  owner_id INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shares(
  id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
  permission TEXT NOT NULL DEFAULT 'read', granted_at TEXT NOT NULL, UNIQUE(doc_id, user_id));
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_name TEXT, action TEXT NOT NULL,
  detail TEXT, ip TEXT, created_at TEXT NOT NULL);
"""

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def one(sql, args=()):
    return db().execute(sql, args).fetchone()

def many(sql, args=()):
    return db().execute(sql, args).fetchall()

def run(sql, args=()):
    cur = db().execute(sql, args)
    db().commit()
    return cur

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    if not con.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        con.execute("INSERT OR IGNORE INTO users(name,email,password,role,created_at) VALUES(?,?,?,?,?)",
                    ("Administrator", "admin@trustvault.local", generate_password_hash("Admin@123"), "admin", now()))
    if not con.execute("SELECT 1 FROM users WHERE email='owner@trustvault.local'").fetchone():
        con.execute("INSERT OR IGNORE INTO users(name,email,password,role,created_at) VALUES(?,?,?,?,?)",
                    ("Default Owner", "owner@trustvault.local", generate_password_hash("Owner@123"), "owner", now()))
    if not con.execute("SELECT 1 FROM users WHERE email='viewer@trustvault.local'").fetchone():
        con.execute("INSERT OR IGNORE INTO users(name,email,password,role,created_at) VALUES(?,?,?,?,?)",
                    ("Default Viewer", "viewer@trustvault.local", generate_password_hash("Viewer@123"), "viewer", now()))
    con.commit()
    con.close()

init_db()

def log(action, detail="", user=None):
    u = user or g.get("user")
    run("INSERT INTO logs(user_id,user_name,action,detail,ip,created_at) VALUES(?,?,?,?,?,?)",
        (u["id"] if u else None, u["name"] if u else "anonymous", action, detail, request.remote_addr, now()))

# ---------- security helpers ----------
def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]

@app.context_processor
def inject():
    return dict(csrf=csrf, CATEGORIES=CATEGORIES)

@app.template_filter("filesize")
def filesize(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"

@app.before_request
def load_user():
    g.user = None
    if session.get("uid"):
        g.user = one("SELECT * FROM users WHERE id=?", (session["uid"],))
        if not g.user:
            session.clear()
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("_csrf", ""), session.get("csrf", "")):
            abort(400, "Invalid form token. Reload the page and try again.")

def login_required(f):
    @functools.wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

def roles_required(*roles):
    def deco(f):
        @functools.wraps(f)
        @login_required
        def w(*a, **k):
            if g.user["role"] not in roles:
                abort(403, "Your role does not have access to this page.")
            return f(*a, **k)
        return w
    return deco

def ext(name):
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""

def access(doc):
    u = g.user
    if u["role"] == "admin":
        return "admin"
    if doc["owner_id"] == u["id"]:
        return "owner"
    s = one("SELECT permission FROM shares WHERE doc_id=? AND user_id=?", (doc["id"], u["id"]))
    if s:
        return "edit" if s["permission"] == "edit" and u["role"] != "viewer" else "read"
    return None

def get_doc(doc_id, need="read", msg=None):
    doc = one("SELECT d.*, u.name AS owner_name FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.id=?", (doc_id,))
    if not doc:
        abort(404, "Document not found.")
    lvl = access(doc)
    if not lvl:
        log("access_denied", f"doc #{doc_id}")
        abort(403, "You don't have access to this document.")
    if RANK[lvl] < RANK[need]:
        log("access_denied", f"doc #{doc_id} needs {need}")
        abort(403, msg or "You don't have permission for this action.")
    return doc, lvl

MANAGE_MSG = "Only the admin or the document owner can manage access to this document."

def visible():
    if g.user["role"] == "admin":
        return "1=1", []
    return "(d.owner_id=? OR d.id IN (SELECT doc_id FROM shares WHERE user_id=?))", [g.user["id"]] * 2

def save_file(f, folder, allowed):
    name = secure_filename(f.filename or "")
    if not name or ext(name) not in allowed:
        return None
    stored = uuid.uuid4().hex + "." + ext(name)
    path = os.path.join(folder, stored)
    f.save(path)
    return name, stored, os.path.getsize(path)

def remove_file(folder, stored):
    try:
        os.remove(os.path.join(folder, stored))
    except OSError:
        pass

# ---------- errors ----------
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def err(e):
    return render_template("error.html", code=e.code, msg=e.description), e.code

@app.errorhandler(413)
def too_big(e):
    return render_template("error.html", code=413, msg="File is too large. The limit is 16 MB."), 413

# ---------- auth ----------
@app.route("/")
def index():
    if not g.user:
        return redirect(url_for("login"))
    if g.user["role"] == "admin":
        return redirect(url_for("admin_home"))
    elif g.user["role"] == "viewer":
        return redirect(url_for("viewer_home"))
    return redirect(url_for("owner_home"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "owner").strip().lower()
        if role not in ("owner", "viewer"):
            role = "owner"
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        if not name or "@" not in email:
            flash("Enter your name and a valid email address.", "error")
        elif len(pw) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif pw != pw2:
            flash("Passwords do not match.", "error")
        elif one("SELECT 1 FROM users WHERE email=?", (email,)):
            flash("That email is already registered. Sign in instead.", "error")
        else:
            cur = run("INSERT INTO users(name,email,password,role,created_at) VALUES(?,?,?,?,?)",
                      (name, email, generate_password_hash(pw), role, now()))
            log("register", f"{email} ({role})", one("SELECT * FROM users WHERE id=?", (cur.lastrowid,)))
            flash(f"Account created as {role.capitalize()}. You can sign in now.", "ok")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        u = one("SELECT * FROM users WHERE email=?", (email,))
        if u and check_password_hash(u["password"], request.form.get("password", "")):
            session.clear()
            session["uid"] = u["id"]
            csrf()
            log("login", u["email"], u)
            return redirect(url_for("index"))
        log("login_failed", email)
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log("logout", g.user["email"])
    session.clear()
    return redirect(url_for("login"))

# ---------- dashboard ----------
@app.route("/dashboard")
@roles_required("admin")
def dashboard():
    c = lambda sql: one(sql)[0]
    failed = c("SELECT COUNT(*) FROM logs WHERE action='login_failed' AND created_at >= datetime('now','localtime','-1 day')")
    stats = dict(docs=c("SELECT COUNT(*) FROM documents"), users=c("SELECT COUNT(*) FROM users"),
                 shares=c("SELECT COUNT(*) FROM shares"), shared_docs=c("SELECT COUNT(DISTINCT doc_id) FROM shares"),
                 logs=c("SELECT COUNT(*) FROM logs"), failed=failed,
                 status="Secure" if failed < 5 else "Review needed")
    recent = many("SELECT * FROM logs ORDER BY id DESC LIMIT 8")
    return render_template("dashboard.html", s=stats, recent=recent)

# ---------- documents ----------
@app.route("/documents")
@login_required
def documents():
    mine = many("SELECT d.*, u.name AS owner_name FROM documents d JOIN users u ON u.id=d.owner_id "
                "WHERE d.owner_id=? ORDER BY d.id DESC", (g.user["id"],))
    shared = many("SELECT d.*, u.name AS owner_name, s.permission FROM documents d JOIN shares s ON s.doc_id=d.id "
                  "JOIN users u ON u.id=d.owner_id WHERE s.user_id=? ORDER BY d.id DESC", (g.user["id"],))
    return render_template("documents.html", mine=mine, shared=shared)

@app.route("/search")
@login_required
def search():
    a = {k: request.args.get(k, "").strip() for k in ("q", "category", "owner", "date_from", "date_to")}
    where, args = visible()
    sql = "SELECT d.*, u.name AS owner_name FROM documents d JOIN users u ON u.id=d.owner_id WHERE " + where
    if a["q"]:
        sql += " AND d.title LIKE ?"; args.append(f"%{a['q']}%")
    if a["category"]:
        sql += " AND d.category=?"; args.append(a["category"])
    if a["owner"]:
        sql += " AND u.name LIKE ?"; args.append(f"%{a['owner']}%")
    if a["date_from"]:
        sql += " AND date(d.created_at)>=?"; args.append(a["date_from"])
    if a["date_to"]:
        sql += " AND date(d.created_at)<=?"; args.append(a["date_to"])
    results = many(sql + " ORDER BY d.id DESC", args)
    return render_template("search.html", a=a, results=results, searched=any(a.values()))

@app.route("/categories")
@login_required
def categories():
    where, args = visible()
    rows = many(f"SELECT d.category, COUNT(*) n FROM documents d WHERE {where} GROUP BY d.category", args)
    counts = {r["category"]: r["n"] for r in rows}
    return render_template("categories.html", counts=counts)

@app.route("/upload", methods=["GET", "POST"])
@roles_required("admin", "owner")
def upload():
    users = many("SELECT id,name,email,role FROM users WHERE id!=? ORDER BY name", (g.user["id"],))
    if request.method == "POST":
        f = request.files.get("file")
        cat = request.form.get("category", "Other")
        if not f or not f.filename:
            flash("Choose a file to upload.", "error")
        elif cat not in CATEGORIES:
            flash("Choose a valid category.", "error")
        else:
            saved = save_file(f, UPLOADS, DOC_EXT)
            if not saved:
                flash("File type not allowed. Allowed: " + ", ".join(sorted(DOC_EXT)), "error")
            else:
                name, stored, size = saved
                title = request.form.get("title", "").strip() or name
                cur = run("INSERT INTO documents(title,filename,stored_name,category,size,owner_id,created_at,updated_at) "
                          "VALUES(?,?,?,?,?,?,?,?)", (title, name, stored, cat, size, g.user["id"], now(), now()))
                perm = "edit" if request.form.get("permission") == "edit" else "read"
                for uid in request.form.getlist("share_with"):
                    if uid.isdigit() and int(uid) != g.user["id"] and one("SELECT 1 FROM users WHERE id=?", (uid,)):
                        run("INSERT OR REPLACE INTO shares(doc_id,user_id,permission,granted_at) VALUES(?,?,?,?)",
                            (cur.lastrowid, int(uid), perm, now()))
                        log("share", f"doc #{cur.lastrowid} -> user #{uid} ({perm})")
                log("upload", f"doc #{cur.lastrowid} {title}")
                flash("Document uploaded.", "ok")
                return redirect(url_for("doc", doc_id=cur.lastrowid))
    return render_template("upload.html", users=users)

@app.route("/doc/<int:doc_id>")
@login_required
def doc(doc_id):
    d, lvl = get_doc(doc_id)
    manage = lvl in ("owner", "admin")
    shares, others = [], []
    if manage:
        shares = many("SELECT s.*, u.name, u.email, u.role FROM shares s JOIN users u ON u.id=s.user_id WHERE s.doc_id=?", (doc_id,))
        others = many("SELECT id,name,email FROM users WHERE id!=? AND id NOT IN (SELECT user_id FROM shares WHERE doc_id=?) ORDER BY name",
                      (d["owner_id"], doc_id))
    return render_template("doc.html", d=d, lvl=lvl, manage=manage, shares=shares, others=others,
                           can_edit=RANK[lvl] >= RANK["edit"])

@app.route("/doc/<int:doc_id>/download")
@login_required
def download(doc_id):
    d, _ = get_doc(doc_id)
    log("download", f"doc #{doc_id} {d['title']}")
    return send_from_directory(UPLOADS, d["stored_name"], as_attachment=True, download_name=d["filename"])

@app.route("/doc/<int:doc_id>/update", methods=["POST"])
@login_required
def doc_update(doc_id):
    d, _ = get_doc(doc_id, "edit", "You only have read access to this document.")
    title = request.form.get("title", "").strip() or d["title"]
    cat = request.form.get("category", d["category"])
    if cat not in CATEGORIES:
        cat = d["category"]
    stored, name, size = d["stored_name"], d["filename"], d["size"]
    f = request.files.get("file")
    if f and f.filename:
        saved = save_file(f, UPLOADS, DOC_EXT)
        if not saved:
            flash("File type not allowed.", "error")
            return redirect(url_for("doc", doc_id=doc_id))
        remove_file(UPLOADS, stored)
        name, stored, size = saved
    run("UPDATE documents SET title=?,category=?,filename=?,stored_name=?,size=?,updated_at=? WHERE id=?",
        (title, cat, name, stored, size, now(), doc_id))
    log("edit", f"doc #{doc_id}")
    flash("Document updated.", "ok")
    return redirect(url_for("doc", doc_id=doc_id))

@app.route("/doc/<int:doc_id>/share", methods=["POST"])
@login_required
def share(doc_id):
    d, _ = get_doc(doc_id, "owner", MANAGE_MSG)
    uid = request.form.get("user_id", "")
    perm = "edit" if request.form.get("permission") == "edit" else "read"
    target = one("SELECT * FROM users WHERE id=?", (uid,)) if uid.isdigit() else None
    if not target or target["id"] == d["owner_id"]:
        flash("Choose a user to share with.", "error")
    else:
        run("INSERT OR REPLACE INTO shares(doc_id,user_id,permission,granted_at) VALUES(?,?,?,?)",
            (doc_id, target["id"], perm, now()))
        log("share", f"doc #{doc_id} -> {target['email']} ({perm})")
        flash(f"Access granted to {target['name']} ({perm}).", "ok")
    return redirect(url_for("doc", doc_id=doc_id))

@app.route("/doc/<int:doc_id>/revoke/<int:user_id>", methods=["POST"])
@login_required
def revoke(doc_id, user_id):
    get_doc(doc_id, "owner", MANAGE_MSG)
    run("DELETE FROM shares WHERE doc_id=? AND user_id=?", (doc_id, user_id))
    log("revoke", f"doc #{doc_id} user #{user_id}")
    flash("Access revoked.", "ok")
    return redirect(url_for("doc", doc_id=doc_id))

@app.route("/doc/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_doc(doc_id):
    d, _ = get_doc(doc_id, "owner", "Only the admin or the document owner can delete this document.")
    remove_file(UPLOADS, d["stored_name"])
    run("DELETE FROM shares WHERE doc_id=?", (doc_id,))
    run("DELETE FROM documents WHERE id=?", (doc_id,))
    log("delete", f"doc #{doc_id} {d['title']}")
    flash("Document deleted.", "ok")
    return redirect(url_for("documents"))

# ---------- admin ----------
@app.route("/logs")
@roles_required("admin")
def logs():
    action = request.args.get("action", "")
    rows = many("SELECT * FROM logs WHERE (?='' OR action=?) ORDER BY id DESC LIMIT 300", (action, action))
    actions = [r[0] for r in many("SELECT DISTINCT action FROM logs ORDER BY action")]
    return render_template("logs.html", rows=rows, actions=actions, action=action)

@app.route("/users")
@roles_required("admin")
def users():
    rows = many("SELECT u.*, (SELECT COUNT(*) FROM documents WHERE owner_id=u.id) AS docs FROM users u ORDER BY u.id")
    return render_template("users.html", rows=rows)

@app.route("/users/<int:uid>/role", methods=["POST"])
@roles_required("admin")
def set_role(uid):
    role = request.form.get("role")
    if role not in ("admin", "owner", "viewer") or uid == g.user["id"]:
        abort(400, "You can't change your own role, and the role must be admin, owner or viewer.")
    run("UPDATE users SET role=? WHERE id=?", (role, uid))
    log("role_change", f"user #{uid} -> {role}")
    flash("Role updated.", "ok")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/delete", methods=["POST"])
@roles_required("admin")
def delete_user(uid):
    if uid == g.user["id"]:
        abort(400, "You can't delete your own account.")
    for d in many("SELECT * FROM documents WHERE owner_id=?", (uid,)):
        remove_file(UPLOADS, d["stored_name"])
        run("DELETE FROM shares WHERE doc_id=?", (d["id"],))
    run("DELETE FROM documents WHERE owner_id=?", (uid,))
    run("DELETE FROM shares WHERE user_id=?", (uid,))
    run("DELETE FROM users WHERE id=?", (uid,))
    log("user_delete", f"user #{uid}")
    flash("User and their documents deleted.", "ok")
    return redirect(url_for("users"))


# OWNER PAGE
@app.route("/owner")
@roles_required("owner")
def owner_home():
    mine = many("SELECT d.*, u.name AS owner_name FROM documents d JOIN users u ON u.id=d.owner_id "
                "WHERE d.owner_id=? ORDER BY d.id DESC", (g.user["id"],))
    shared = many("SELECT d.*, u.name AS owner_name, s.permission FROM documents d JOIN shares s ON s.doc_id=d.id "
                  "JOIN users u ON u.id=d.owner_id WHERE s.user_id=? ORDER BY d.id DESC", (g.user["id"],))
    return render_template("owner.html", mine=mine, shared=shared)

# VIEWER PAGE
@app.route("/viewer")
@roles_required("viewer")
def viewer_home():
    shared = many("SELECT d.*, u.name AS owner_name, s.permission FROM documents d JOIN shares s ON s.doc_id=d.id "
                  "JOIN users u ON u.id=d.owner_id WHERE s.user_id=? ORDER BY d.id DESC", (g.user["id"],))
    return render_template("viewer.html", shared=shared)

# ADMIN PAGE
@app.route("/admin")
@roles_required("admin")
def admin_home():
    return render_template("admin.html")

# ---------- profile ----------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            run("UPDATE users SET name=? WHERE id=?", (name, g.user["id"]))
            log("profile_update", "name")
            flash("Profile saved.", "ok")
        return redirect(url_for("profile"))
    return render_template("profile.html")

@app.route("/profile/avatar", methods=["POST"])
@login_required
def avatar_upload():
    f = request.files.get("avatar")
    saved = save_file(f, AVATARS, IMG_EXT) if f and f.filename else None
    if not saved:
        flash("Choose a PNG, JPG, GIF or WEBP image.", "error")
    else:
        if g.user["avatar"]:
            remove_file(AVATARS, g.user["avatar"])
        run("UPDATE users SET avatar=? WHERE id=?", (saved[1], g.user["id"]))
        log("avatar_update")
        flash("Profile image updated.", "ok")
    return redirect(url_for("profile"))

@app.route("/avatar/<name>")
@login_required
def avatar(name):
    return send_from_directory(AVATARS, secure_filename(name))

@app.route("/profile/password", methods=["POST"])
@login_required
def password():
    cur, new, conf = (request.form.get(k, "") for k in ("current", "new", "confirm"))
    if not check_password_hash(g.user["password"], cur):
        flash("Current password is incorrect.", "error")
    elif len(new) < 8:
        flash("New password must be at least 8 characters.", "error")
    elif new != conf:
        flash("New passwords do not match.", "error")
    else:
        run("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new), g.user["id"]))
        log("password_change")
        flash("Password updated.", "ok")
    return redirect(url_for("profile"))

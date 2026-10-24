# 🛡️ TrustVault — Secure Document Vault & Access Management

TrustVault is a secure, role-based document management web application built with **Python (Flask)** and **SQLite**. It provides safe document uploading, categorical organization, comprehensive audit logging, and granular access control with permission granting and revoking.

---

## 📸 Visual Walkthrough & Screenshots

### 1. Clean & Secure Sign In
A clean, official white layout with secure authentication and high-contrast inputs for effortless typing:

---

### 2. Form Input & Validation
Clean white input styling with clear slate typography, password mask toggling, and input security:

---

### 3. User Dashboard & "My Documents"
Organized into two distinct categories: **Uploaded by me** (with full owner permissions to edit, share, or delete) and **Shared with me** (with granted read/edit access):

---

## 🎯 The Problem & What TrustVault Solves

In collaborative environments, unauthorized document access or accidental file deletion can compromise sensitive organizational data. TrustVault addresses this with:
1. **Three-Tier User Roles**: Distinct separation of privileges between **Admin**, **Owner**, and **Viewer**.
2. **Access Delegation**: Document owners can grant or revoke `read` or `edit` permissions for specific users.
3. **Strict Privilege Enforcement**: Only administrators and document owners can manage document permissions; unauthorized attempts automatically trigger a 403 Forbidden protection error.
4. **Audit & Activity Logs**: Full visibility into user login, logout, and document actions for auditing.
5. **Modern, Responsive UI**: Mobile-friendly navigation drawer, collapsible sidebar, and a clean, high-contrast white aesthetic.

---

## 👥 Role & Permissions Matrix

| Feature / Action | Admin | Owner (Uploader) | Viewer |
| :--- | :---: | :---: | :---: |
| **System Dashboard & Statistics** | ✅ Full Access | ❌ | ❌ |
| **Upload Documents** | ✅ | ✅ | ❌ |
| **Delete Own Document** | ✅ | ✅ | ❌ |
| **Grant / Revoke Sharing Access** | ✅ Any Document | ✅ Own Documents Only | ❌ |
| **Edit Document (Rename, Reupload)** | ✅ | ✅ (If owner or granted `edit`) | ❌ |
| **View & Download Shared Documents** | ✅ | ✅ | ✅ (If granted access) |
| **Activity & Audit Logs** | ✅ Full Logs | ❌ | ❌ |
| **Manage Users & Role Assignment** | ✅ | ❌ | ❌ |

---

## 🚀 How to Run the Project

### Prerequisites
- **Python 3.10+** installed
- Git (optional)

### Quick Start (Windows PowerShell)

```powershell
# 1. Navigate to the project directory
cd TrustVault

# 2. Activate the virtual environment
.\venv\Scripts\Activate.ps1

# (Optional: if dependencies are not yet installed)
python -m pip install -r requirements.txt

# 3. Start the application
python run.py
```

### Quick Start (Command Prompt / Linux / macOS)
```bash
# Windows cmd:
venv\Scripts\activate.bat
python run.py

# macOS / Linux:
source venv/bin/activate
python run.py
```

Now open your web browser at:
👉 **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**

---

## 🔑 Default Credentials

A default administrator account is initialized automatically on first startup:

- **Email**: `admin@trustvault.local`
- **Password**: `Admin@123`
*(You can update this password at any time in the **Profile** section).*

New registrations through the **"Create an account"** link receive the **Owner** role by default.

---

## 📁 Project Directory Structure

```text
TrustVault/
│
├── app/
│   ├── static/
│   │   └── style.css            # Responsive, modern white-theme stylesheet
│   ├── templates/               # Jinja2 HTML templates
│   │   ├── base.html            # Core layout with responsive navigation drawer
│   │   ├── login.html           # Sign in interface
│   │   ├── register.html        # New user registration
│   │   ├── dashboard.html       # Admin metrics & security stats
│   │   ├── documents.html       # My documents & shared documents view
│   │   ├── doc.html             # Document details & access permission manager
│   │   ├── upload.html          # Document upload interface
│   │   ├── search.html          # Multi-filter search (category, owner, date)
│   │   ├── categories.html      # Category management
│   │   ├── users.html           # User & role administration
│   │   ├── logs.html            # Audit activity trail
│   │   └── profile.html         # User profile and password updater
│   └── __init__.py              # Core application, routes, models & auth logic
│
├── instance/
│   └── trustvault.db            # SQLite database (auto-created)
│
├── screenshots/                 # Application visual walkthrough images
│   ├── 01_login_clean.png
│   ├── 02_login_typing.png
│   └── 03_my_documents_dashboard.png
│
├── requirements.txt             # Python package dependencies
├── running.text                 # Quick execution reference file
├── README.md                    # Project documentation & guide
└── run.py                       # Application entry point
```

---

## 🔒 Security Architecture
- **CSRF Token Verification**: Every state-changing form includes automatic CSRF validation.
- **Password Security**: Passwords are securely hashed with industry-standard Werkzeug / PBKDF2 hashing.
- **Isolated Storage**: Uploaded files are validated, renamed safely, and saved in dedicated, non-executable directories with a 16MB file-size limit.
- **Access Control Layer**: Endpoints verify user roles before granting administrative actions, throwing HTTP 403 Forbidden if unauthorized users attempt to modify permissions.

---

## 🛠️ Tech Stack
- **Backend**: Python, Flask, Jinja2
- **Database**: SQLite3
- **Frontend**: Clean Semantic HTML5, Vanilla Responsive CSS (Zero external CSS bloat, ultra fast load times)
"# TrustVault" 

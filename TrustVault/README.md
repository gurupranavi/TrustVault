# TrustVault – secure document vault (Flask + SQLite)

## Run (Windows PowerShell)
```
cd path\to\TrustVault
python -m venv venv
venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run.py
```
Open http://127.0.0.1:5000/

The database (`instance/trustvault.db`) and upload folders are created automatically on first run.

## Default admin
- Email: `admin@trustvault.local`
- Password: `Admin@123`  (change it in Profile after first login)

## Roles
| Role   | Can do |
|--------|--------|
| admin  | Everything: dashboard, all documents, manage users and roles, activity logs, grant/revoke access on any document |
| owner  | Upload, edit, delete and share own documents; grant/revoke access on own documents. New registrations get this role |
| viewer | Read-only: view and download documents shared with them. Cannot upload |

Anyone other than the admin or the document owner who tries to grant or revoke access gets a 403 error.
Share permissions: `read` (view/download) or `edit` (rename, change category, replace the file). Edit access is capped to read for users with the viewer role.

## Structure
```
run.py                  entry point
app/__init__.py         routes, database, security
app/templates/*.html    pages
app/static/style.css    black + emerald theme, responsive
```
Set `SECRET_KEY` as an environment variable in production. Max upload size is 16 MB.

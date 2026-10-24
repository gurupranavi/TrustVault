# 📝 PROMPTS.md — AI Interaction & Engineering Log

This log documents the iterative development of **TrustVault**, capturing prompt interactions, AI hallucinations/errors, diagnostic analysis, and the actual engineering corrections applied to the codebase.

---

### Entry 1: Authorization & IDOR Protection in Document Access
- **Date**: 2026-10-21
- **What I asked for**:
  "Create the document detail and download routes in Flask. Ensure that only users with permissions can view and download files."
- **What the tool produced**:
  The AI generated basic Flask routes using `@login_required` and queried `Document.query.get(doc_id)`. If the document was found, it directly served the file with `send_from_directory()`.
- **What was wrong with it**:
  **Critical Authorization Bypass (IDOR)**: The AI failed to verify whether the logged-in user actually owned the document or had an active share record. Any authenticated user could enumerate sequential IDs (e.g., `/doc/1/download`, `/doc/2/download`) and download any private file in the vault.
- **What I did instead**:
  Engineered a centralized access resolution function `access(doc)` with a hierarchical rank system (`read: 1, edit: 2, owner: 3, admin: 4`). Created `get_doc(doc_id, need="read")` which aborts with HTTP 403 if the user is neither admin, owner, nor a recipient of an active share. Tested via `test_viewer_cannot_access_unshared_doc`.
- **Commit Reference**: `feat(auth): implement hierarchical RBAC and IDOR prevention`

---

### Entry 2: Privilege Escalation & Role Capping in Share Delegation
- **Date**: 2026-10-21
- **What I asked for**:
  "Implement document sharing so document owners can share files with other users with read or edit permissions, and revoke them anytime."
- **What the tool produced**:
  The AI provided endpoints `POST /doc/<id>/share` and `POST /doc/<id>/revoke/<user_id>` that directly inserted into a `shares` table based on whatever permission string was passed in the form.
- **What was wrong with it**:
  1. **Privilege Escalation**: If an owner granted `edit` permission to a user whose global role was `viewer`, the viewer gained file-editing and replacement capabilities, violating the strict specification that viewers must remain read-only.
  2. **Missing Ownership Check on Revocation**: The AI did not check whether the user calling `/revoke` was the owner of the document, allowing any shared user to revoke everyone else's access.
- **What I did instead**:
  Implemented strict role capping:
  ```python
  if s:
      return "edit" if s["permission"] == "edit" and u["role"] != "viewer" else "read"
  ```
  Enforced `get_doc(doc_id, "owner", MANAGE_MSG)` on both `/share` and `/revoke` routes so only the document owner or system admin can alter permissions. Verified with `test_viewer_edit_role_capping` and `test_stranger_cannot_manage_access`.
- **Commit Reference**: `fix(security): enforce viewer role capping and secure access revocation`

---

### Entry 3: Security Audit Trail & Access Failure Logging
- **Date**: 2026-10-22
- **What I asked for**:
  "Add an activity and audit logging system to record logins, logouts, uploads, and unauthorized access attempts for the admin."
- **What the tool produced**:
  The AI suggested writing log lines directly to a plain text file `audit.log` using standard Python `logging`.
- **What was wrong with it**:
  Plain-text logging in a web server environment causes file lock contentions under concurrent requests. More importantly, it made it impossible for the admin dashboard to query, paginate, filter by action (`login_failed`, `access_denied`), or correlate IP addresses and timestamps in real-time SQL queries.
- **What I did instead**:
  Designed a dedicated `logs` table in SQLite (`user_id`, `user_name`, `action`, `detail`, `ip`, `created_at`). Created a central `log(action, detail)` helper that automatically captures `request.remote_addr`. Wired it up to capture both successful actions and unauthorized attempts (`access_denied`, `login_failed`), feeding the admin `/logs` view and security dashboard.
- **Commit Reference**: `feat(audit): implement structured SQLite audit trail with admin filters`

---

### Entry 4: Dashboard Theme Color Specification
- **Date**: 2026-10-22
- **What I asked for**:
  "Style the dashboard and pages using a modern color palette with emerald green and black."
- **What the tool produced**:
  The AI produced a CSS theme utilizing pitch black backgrounds paired with high-saturation neon yellow highlights (`#ffff00`) and aggressive green borders.
- **What was wrong with it**:
  The generated styles completely deviated from the requested emerald palette, resulting in poor visual hierarchy and illegible contrast against the neon yellow buttons.
- **What I did instead**:
  Re-defined CSS custom variables in `:root` with proper emerald tones (`#10b981`, `#34d399`), deep neutral dark panel tones (`#0d1210`), and clean typography before later transitioning to the production-grade white theme.
- **Commit Reference**: `style(ui): fix color palette and card contrast`

---

### Entry 5: Modern Responsive White Theme & Input Text Visibility Fix
- **Date**: 2026-10-23
- **What I asked for**:
  "Transform TrustVault to have a clean, official white background and responsive layout matching modern SaaS standards (like shoply-auto-sre)."
- **What the tool produced**:
  The AI changed body background to `#ffffff`, but left form inputs styled with `background: #080c0a` and dark gray text (`#212529`).
- **What was wrong with it**:
  Typing text in form fields (such as Email and Password on `/login`) was rendered completely invisible because dark text was typed on a black input box inside a white card. The mobile drawer also lacked a backdrop overlay to dismiss the navigation menu when tapped outside.
- **What I did instead**:
  Replaced input styles with crisp white backgrounds (`#ffffff !important`), dark slate typography (`#0f172a !important`), subtle border accents (`#cbd5e1`), and blue focus rings. Added a responsive mobile drawer with `.nav-backdrop` overlay and tested responsiveness on desktop and mobile viewports.
- **Commit Reference**: `style(theme): modernize to clean white UI and resolve input visibility`

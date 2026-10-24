# Role Definitions for TrustVault

TrustVault uses three distinct user roles to implement **role‑based access control (RBAC)**:

| Role | Description | Primary Permissions |
|------|-------------|---------------------|
| **admin** | System administrator with full control over the application. | - Access the **System Dashboard** and all audit logs<br/>- Upload, edit, **and delete any document**<br/>- Grant or revoke sharing permissions on **any** document<br/>- Manage users (change roles, delete accounts) |
| **owner** | The user who originally uploaded a document. Also the default role for newly registered users. | - Upload documents<br/>- Edit or delete **their own** documents<br/>- Grant or revoke sharing permissions **only on documents they own**<br/>- View and download documents they own **and** any documents shared with them (read or edit permission) |
| **viewer** | A regular user that can only view documents that have been explicitly shared with them. | - Cannot upload new documents<br/>- Cannot edit or delete any document<br/>- Can view/download documents **only if** a sharing record exists with permission `read` or `edit` |

The role is stored in the `users.role` column of the SQLite database and is enforced throughout the code via the `roles_required` decorator and the `access` helper function.

*Users can choose their role (`Document Owner` or `Viewer`) directly during registration at `/register` without needing an administrator to reassign it in `/users`. Default test accounts are also pre-seeded (`admin@trustvault.local`, `owner@trustvault.local`, `viewer@trustvault.local`).*

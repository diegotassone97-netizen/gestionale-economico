# Security Specification - Controllo Economico & Gestione

## 1. Data Invariants
1. **Authenticated Access**: Unauthenticated requests to read, write, update or delete any operational financial data (`gestionale_fatturato`, `gestionale_spese`, `gestionale_utenti_autorizzati`) must be unconditionally denied.
2. **Admin Privilege**: The designated administrator (`DIEGOTASSONE97@gmail.com` with `email_verified == true`, or records in `/admins/{uid}`) has full read/write management across revenues, expenses, and user whitelist.
3. **Verified Email Mandate**: Any write operation requires `request.auth.token.email_verified == true`.
4. **Authorized Collaborators**: Collaborators on the active authorized users whitelist can read revenues and expenses and create or edit entries, but cannot delete or modify users or escalation paths.
5. **No Identity Spoofing**: `createdBy` in newly created revenue or expense entries must match `request.auth.uid` or the authenticated email.
6. **Input Boundaries**: Financial figures must be numeric and non-negative. Strings must have strict bounds (`description` <= 300 chars, `notes` <= 1000 chars, etc.).
7. **Document ID Hardening**: Document IDs must be alphanumeric strings <= 128 characters.

## 2. The "Dirty Dozen" Threat Payloads (Must Return PERMISSION_DENIED)
1. **Unauthenticated Read**: Attempt to read `/gestionale_fatturato` without `request.auth`.
2. **Unauthenticated Write**: Attempt to write to `/gestionale_spese` without authentication.
3. **Unverified Email Injection**: Attempt to write as `DIEGOTASSONE97@gmail.com` with `email_verified: false`.
4. **Identity Spoofing**: Attempt to create a revenue entry with `createdBy: "victim_user"` while authenticated as `"attacker_uid"`.
5. **Admin Whitelist Escalation**: Non-admin user attempting to write a new record to `/admins/{uid}` or elevate themselves to `role: "admin"`.
6. **Malicious Negative Amount**: Writing a revenue entry with a negative amount (`amount: -50000`).
7. **Giant String Denial of Wallet**: Writing an entry with a 50KB description string to exhaust storage or bandwidth.
8. **Invalid Path/ID Injection**: Creating a document with ID `../../etc/passwd` or non-regex compliant characters.
9. **Ghost/Shadow Field Injection**: Adding an unpermitted field `isSuperUser: true` into a revenue document.
10. **Suspended User Write**: An authenticated user marked with `status: "suspended"` attempting write operations.
11. **Collaborator User Deletion**: A collaborator attempting to delete an authorized user record.
12. **Blanket Query Scraping**: Attempting an unrestricted list query without authenticated context.

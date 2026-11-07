# SV — Share · View: Project Review

This guide describes the project as implemented in this repository: its
architecture, tools, data, workflows, API, operations, and known constraints.
It is a code-oriented overview, not a deployment certification or a guarantee
that a particular installation is secure.

## 1. Purpose and architecture

SV is a web application for storing encrypted documents and sharing them with
named, registered users. Owners manage their documents and choose per-recipient
View or Edit access. Recipients must authenticate and enter the document PIN.
Staff have a separate platform-control UI for account moderation, document
management, and audit review.

The backend is the authorization boundary. React controls are for usability:
the API rechecks identity, ownership/share status, expiry, permission, and (where
required) PIN on protected operations.

```text
Browser
  React / React Router frontend
    local dev: Vite (proxies /api to Django)
    production: Nginx serves built single-page application
           |
           | /api/
           v
  Django REST API / Gunicorn
    |-- SQLite (local) or PostgreSQL (Compose)
    |-- encrypted files and edit-replacement storage
    |-- audit records + independent checkpoint file

Production entry point: Caddy
  /api/, /admin/, /static/, /media/ -> Django
  all other paths                    -> frontend
```

In the Docker deployment, PostgreSQL, uploaded files, the audit checkpoint,
and Caddy state use named persistent volumes. The project is currently
single-host; these volumes are not a substitute for off-host backups.

## 2. Tools and dependencies

| Tool | Purpose in this project |
| --- | --- |
| Python / Django | Backend runtime, ORM, accounts/password validation, migrations, settings, admin, and WSGI/ASGI entry points. |
| Django REST Framework | JSON and multipart API, serializers, validation, viewsets, permission checks, and structured API errors. |
| SimpleJWT | Access/refresh bearer tokens, extended here with per-account token versions and password-change invalidation. |
| `cryptography` | AES-256-GCM document encryption/decryption and authenticated ciphertext validation. |
| SQLite | Local development database default. |
| PostgreSQL / Psycopg | Relational database for the provided Compose deployment. |
| React / React Router | Sign-in, personal vault, recipient, and administration screens. |
| Vite | Frontend development server, build, and development API proxy. |
| Axios | Shared API client; attaches access token and attempts a single refresh after eligible 401 responses. |
| Tailwind CSS / PostCSS / Autoprefixer | Utility styling and CSS build pipeline. |
| Framer Motion / Lucide React | UI motion and icon components. |
| ESLint | Frontend linting, including recommended JavaScript and React Hooks rules. |
| Gunicorn | Production WSGI process in the backend container. |
| WhiteNoise | Django static asset serving in non-debug operation. |
| Nginx | Serves compiled frontend assets and falls back to `index.html` for client-side routes. |
| Caddy | Public reverse proxy, automatic HTTPS, redirects, and JSON access logs. |
| Docker Compose | Runs database, API, frontend, and proxy with service health dependencies and persistent volumes. |

Root `package.json` forwards `dev`, `build`, and `lint` into `frontend`.
Frontend dependency versions/scripts are in `frontend/package.json`; backend
dependencies are in `backend/requirements.txt`.

## 3. Screens, roles, and capabilities

### Sign-in and registration (`/auth`)

Users sign in with username/password or create an account. Email is optional.
The UI shows password guidance and checks confirmation, while the server
remains authoritative through Django password validators. Email verification
and self-service password reset are not configured.

### User dashboard (`/`)

- Upload a document and choose a category.
- List owned documents; edit title/category, download, or permanently delete.
- Set/remove a six-digit PIN.
- Share with a registered username, choose View or Edit, optionally set that
  recipient's expiry, and revoke an active share.
- Review documents shared with the current account; enter a PIN to download.
  Edit recipients can replace the owner's original while the grant is active.
- View relevant activity and the rolling 24-hour event count.
- Refresh data manually, on window focus, and every 15 seconds while visible.

The visible dashboard's document filters are primarily client-side. The API
also implements server-side search, owner, category, and date filters for
document collections; not every filter is exposed as a UI control.

### Administration portal (`/control`)

Staff-only portal with platform metrics; paginated/searchable users and
documents; audit search; document download, metadata update, replacement,
deletion and share revocation; and account warning, timeout, clear-timeout,
block and unblock actions. API endpoints independently enforce staff
permissions. Moderation protects staff/superuser accounts and disallows
self-moderation.

The Django Admin site is `/admin/`; it provides additional database-level
controls. Some destructive Admin actions are superuser-only.

### Roles

| Role | Capabilities |
| --- | --- |
| Owner | Manage own documents and PINs; grant/revoke named users' access; set role and per-recipient expiry. |
| Viewer | Access an active grant and download after entering the PIN. Cannot replace or manage the owner's original. |
| Editor | Viewer access plus replacement of the shared original while the owner's Edit grant is active and the PIN is correct. |
| Staff administrator | Platform management and moderation via `/control`; privileged document operations are audited and may bypass PIN checks. |
| Superuser | Staff capabilities plus Django Admin access. |

Shares are not public links. Expiry is per recipient and enforced by the API on
protected requests. Categories organize documents but are not access controls.

## 4. Data model

Models live in `backend/api/models.py`; schema evolution is captured in
`backend/api/migrations/`.

- `SecureFile`: owner, title/category, stored-file reference, byte size,
  encryption version/algorithm, upload time, and optional hashed PIN.
- `FileShare`: file/recipient pair, View/Edit permission, expiry/revocation,
  and failed-PIN/lockout state. A database uniqueness constraint allows one
  share record per file and recipient.
- `SharedFileRevision`: encrypted edited-copy metadata linked to source,
  share, and editor.
- `AuditLog`: event/actor/owner snapshots, action/outcome, peer address,
  timestamp/details, previous hash, and integrity HMAC.
- `AuditChainState`: chain head.
- `AuthTokenVersion`: per-account token revocation counter.
- `UserModeration`: warning count, timeout, note, and staff actor.

Use Django migrations for schema changes; do not modify production schema by
hand.

## 5. Main workflows

### Authentication and sessions

1. `POST /api/register/` validates fields/password and creates a Django user.
2. `POST /api/token/` authenticates and issues access/refresh tokens containing
   the account token version; successful login is audited.
3. Axios adds the access token as a bearer header. If an eligible API request
   returns 401, it tries `POST /api/token/refresh/` once and retries that
   request once.
4. The backend checks that the account exists and is active, is not timed out,
   has not changed its password since issuance, and still has the token version
   carried in the token.
5. Tokens are held in `sessionStorage`, so they do not persist like
   `localStorage` across browser sessions. The service removes any legacy token
   keys from `localStorage`.
6. `POST /api/logout/` increments the account's token version, invalidating
   previously issued tokens across sessions/devices. Password changes also
   invalidate them.

### Upload and download

1. The browser sends multipart form data to `POST /api/files/`.
2. Serializer validation rejects empty files, missing/long filenames, and
   files above `MAX_FILE_UPLOAD_SIZE` (100 MiB by default).
3. `backend/api/crypto.py` encrypts the stream before storage using AES-256-GCM,
   random 12-byte nonce, 16-byte tag, 64 KiB chunks, and an 8 MiB spooled
   temporary-file threshold.
4. The encrypted object is written under a generated name, not the original
   name. Database metadata identifies the format version.
5. An authorized download reads/decrypts the object and streams it as an
   attachment. GCM authentication failure is treated as an unsafe/corrupt
   stored object, not as a successful download.
6. Delete removes original and associated edited-copy storage, records an audit
   event, then deletes the database object and cascading relations.

The version 1 file envelope is marker `TFY1`, nonce, ciphertext, then tag.
Version 0 files are legacy plaintext for compatibility; re-upload to store an
encrypted copy. Media storage is not intended to be a public file server.

### PIN and sharing

1. The owner sets a six-digit numeric PIN. Django stores a password hash; the
   API does not return the PIN.
2. A share requires a PIN to exist and a registered recipient username.
3. The backend creates or updates the unique file/recipient grant, permission,
   and optional expiry. Re-sharing can change role, reactivate a grant, and
   reset lockout state.
4. Recipients list only active grants. Download and replacement require the
   PIN. Five incorrect attempts lock that share for 15 minutes; a successful
   check clears lockout.
5. View allows download only. Edit permits the recipient to replace the
   owner's original while the grant is active. The replacement is encrypted
   before storage and the prior object is removed after update.
6. Revocation/expiry block subsequent requests; they cannot recall data already
   downloaded or an in-progress response. Removing the PIN revokes active
   shares for that document.

**Revision-history caveat:** the model and UI support edited-copy/revision
records, but the normal recipient replacement workflow currently updates the
shared original directly. There is no production-path creation of
`SharedFileRevision` records in the current implementation, so replacements
should not be assumed to produce a browsable prior-version history.

### Audit trail

`record_audit` is used for successful and failed operations. The DRF exception
handler records common 401/403/404/405/429 denials; middleware records denied
admin/direct-media requests; the failed-login signal records the attempted
username without storing the password.

For each event, SV deterministically serializes event fields, calculates an
HMAC-SHA256 over the event and previous event hash, advances the database chain
head, and appends the event ID/hash pair to a separate checkpoint file.
`manage.py verify_audit_chain` checks the database chain, HMAC, head, and
checkpoint agreement. The separate checkpoint helps detect database-only
alteration, but does not defend against an attacker controlling the backend
host, signing key, and checkpoint volume. Independent WORM/append-only export
is not implemented.

## 6. API route map

All API routes are under `/api/`. Protected endpoints require authentication
unless stated otherwise.

| Route | Purpose |
| --- | --- |
| `POST /register/`, `/token/`, `/token/refresh/` | Registration, login, refresh. |
| `GET /account/`, `POST /logout/` | Account summary and global token revocation. |
| `/files/` | Owner-scoped list/create/detail/update/delete. |
| `/files/{id}/download/` | Download owned document. |
| `/files/{id}/passcode/` | Set/remove owner PIN. |
| `/files/{id}/share/` | List/create/update grants for an owned file. |
| `/files/{id}/revisions/` | List edited-copy records for owned file. |
| `/shares/`, `/shares/{id}/` | List owned shares and revoke one. |
| `/shared-with-me/` | List active recipient shares. |
| `/shared-with-me/{id}/download/` | PIN-protected recipient download. |
| `/shared-with-me/{id}/replace/` | PIN/Edit-protected replacement. |
| `/shared-with-me/{id}/revisions/` | List revision records visible to recipient. |
| `/revisions/{id}/download/` | Download an authorized revision object. |
| `/activity/summary/`, `/logs/` | User-relevant activity. |
| `/admin/overview/`, `/admin/audit/` | Staff metrics, accounts, and audit search. |
| `/admin/documents/`, `/admin/documents/{id}/` | Staff document inventory, metadata update, deletion. |
| `/admin/documents/{id}/download/`, `/replace/` | Staff download/replacement. |
| `/admin/shares/{id}/action/` | Staff revoke share. |
| `/admin/users/{id}/action/` | Staff moderation. |
| `/admin/` | Django Admin site. |

Object queries are scoped on the server to owner, recipient, or staff authority.
Some inaccessible IDs return 404 to avoid confirming another user's objects.

## 7. Repository map

```text
backend/core/                 Django settings, root URLs, WSGI/ASGI
backend/api/models.py          Database models
backend/api/serializers.py     Input/output contracts and validation
backend/api/views.py           API endpoints, workflows, authorization and audit calls
backend/api/crypto.py          Encrypted file format and streaming operations
backend/api/audit_integrity.py HMAC chain and checkpoint verification
backend/api/authentication.py  JWT/account/token-version checks
backend/api/middleware.py      Denied media/admin audit handling
backend/api/signals.py         Failed-login audit handling
backend/api/migrations/        Database schema/data evolution
backend/api/tests.py           Backend regression tests
backend/api/management/        Bootstrap-admin and audit-verifier commands
frontend/src/App.jsx           Routes and expired-auth event handling
frontend/src/pages/            Auth, user dashboard, admin dashboard
frontend/src/services/         API, auth and tab-session token storage
docker-compose.yml             PostgreSQL/backend/frontend/Caddy deployment
Caddyfile                      HTTPS reverse-proxy routes and logging
.env.example                   Required deployment settings template
README.md                      Setup and product workflows
THREATS.md                     Threat assumptions and accepted security limits
DEPLOY_ORACLE_FREE_TIER.md     OCI A1 + DuckDNS deployment checklist
```

## 8. Configuration and operations

| Setting | Purpose |
| --- | --- |
| `DJANGO_DEBUG` | Development defaults; production should be false. |
| `DJANGO_SECRET_KEY` | Django secret material; required in production. |
| `FILE_ENCRYPTION_KEY` | URL-safe base64 value decoding to exactly 32 bytes. Keep unchanged with stored files. |
| `AUDIT_LOG_HMAC_KEY` | Independent production HMAC key; distinct from Django key. |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated accepted request hosts. |
| `CSRF_TRUSTED_ORIGINS` | Trusted HTTPS origins for Django Admin CSRF. |
| `CORS_ALLOWED_ORIGINS` | Cross-origin browser clients; production same-origin default is empty. |
| `DATABASE_*` | Engine, database, user, password, host, and port. |
| `MEDIA_ROOT` | Encrypted file storage root. |
| `MAX_FILE_UPLOAD_SIZE` | Maximum accepted upload size in bytes. |
| `AUDIT_CHECKPOINT_PATH` | Separate checkpoint file location. |
| `GUNICORN_WORKERS`, `SECURE_HSTS_SECONDS` | Production process count and HSTS duration. |
| `VITE_API_BASE_URL` | Frontend build-time API base; default is `/api/`. |

Never commit `.env` or private credentials. Back up the database, encrypted
media, matching encryption key, audit key, and checkpoint. The complete setup,
Docker commands, and OCI-specific launch steps are in [README](./README.md) and
[DEPLOY_ORACLE_FREE_TIER.md](./DEPLOY_ORACLE_FREE_TIER.md).

Common local commands (PowerShell):

```powershell
py -m venv backend\venv
backend\venv\Scripts\python.exe -m pip install -r backend\requirements.txt
cd backend
..\backend\venv\Scripts\python.exe manage.py migrate
..\backend\venv\Scripts\python.exe manage.py runserver 0.0.0.0:8000
```

In another terminal:

```powershell
cd frontend
npm ci
npm run dev
npm run lint
npm run build
```

Backend verification:

```powershell
cd backend
..\backend\venv\Scripts\python.exe manage.py check
..\backend\venv\Scripts\python.exe manage.py test
..\backend\venv\Scripts\python.exe manage.py verify_audit_chain
```

## 9. Testing and known limits

The backend tests cover registration/password rules; ownership boundaries;
upload size/encryption/decryption and legacy files; token refresh/logout and
revocation; shares, PIN failure/lockout, expiry and replacement; audit-chain
tampering and checkpoint detection; staff tools; moderation; and activity
counts. The frontend scripts provide ESLint and a production Vite build.

Important limitations and operational observations:

- The local database's audit chain is known to fail verification at event 63;
  its cause is unknown. Preserve it for investigation and do not rewrite or
  re-sign historical records. A fresh production database is recommended.
- Encryption is at rest, not end-to-end: the live backend holds the AES key and
  decrypts authorized downloads.
- Audit HMAC/checkpoint integrity is not protection against compromise of the
  application host, signing key, or checkpoint storage.
- Revocation blocks future requests but cannot retrieve a copy already
  downloaded.
- Docker Compose is a single-host deployment with no built-in managed backup,
  multi-region failover, or independent audit replication.
- Session storage reduces token persistence but is not protection against
  malicious scripts running in the application's origin.
- HSTS subdomain and preload options require a domain-wide HTTPS commitment;
  enable them only after confirming all affected hostnames are ready.

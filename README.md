# SV — Share · View

**SV means Share and View.** SV is a Django REST API and React web client for encrypted file storage and registered-user sharing. New uploads are encrypted on the server with AES-256-GCM. Owners can protect each file's shares with a private six-digit PIN, share with another SV account, optionally set an expiry, and revoke access; recipients must enter the PIN to download and cannot edit or delete the owner's copy.

For the architecture, data model, API map, tools, workflows, configuration, and implementation caveats, see the [Project Review](./PROJECT_REVIEW.md).

Planning a no-cost Oracle Cloud deployment? See the [Oracle Free Tier + DuckDNS deployment checklist](./DEPLOY_ORACLE_FREE_TIER.md).

## Requirements

- Python 3.10 or later
- Node.js 20.19+ or 22.12+
- PostgreSQL is optional for local development; SQLite is used by default

## Roles and document access

Every user must sign in. Documents and search results are scoped to the signed-in user's owned documents and active shares; knowing a document ID does not grant access.

| Role | Capabilities |
| --- | --- |
| Administrator (staff) | Use the SV portal to review all documents and shares, download and replace file contents, edit metadata, revoke recipient grants, delete documents, search/paginate accounts, issue warnings, time out or block/unblock non-admin accounts, and review platform audit activity. Administrator access bypasses owner and recipient PIN checks; every document-management action is recorded. |
| Superuser | Has staff capabilities and can access Django Admin for additional database-level management. |
| Document owner | Upload, categorize, rename, search, download, and delete their own documents; grant or revoke named users' view/edit shares; set and manage each document's PIN. |
| Viewer (recipient with View) | View shared document metadata and download it after entering the document PIN. Cannot edit, replace, delete, or reshare the owner's document. |
| Editor (recipient with Edit) | Has viewer access and may submit a replacement after entering the PIN. The owner grants and revokes this ability by setting the share to Edit or View. |

Owners can search owned documents by title, owner username, category, and upload date, and recipients can apply the same filters only to active shares. Uploads and replacements reject empty files, filenames over 255 characters, and files over the configured size limit. Uploads, downloads, edits, deletions, share changes, and denied access are included in the audit trail.

Categories are organizational labels such as **Contracts**, **Reports**, or **Invoices**. They make it easier to group and filter documents; they do not grant, restrict, or otherwise change access. The dashboard's activity count is the number of events in the last rolling 24 hours; the activity trail shows the latest 50 relevant events. The admin portal likewise reports the rolling 24-hour event count and shows the latest 100 platform events, with search.

## Accounts and passwords

Create an account from the SV sign-in page with a username and password; email is optional. Passwords must be at least 8 characters and cannot be entirely numeric. Django also rejects common passwords and passwords too similar to the username. The account form shows the requirements, checks password confirmation, and the server remains the final validator. Sign in uses the username and password. Email verification and self-service password reset are not currently configured.

## Run locally

From the project root, install the backend dependencies:

```powershell
py -m venv backend\venv
backend\venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

Generate and save the encryption key **once** in PowerShell:

```powershell
$key = (backend\venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())").Trim()
[Environment]::SetEnvironmentVariable("FILE_ENCRYPTION_KEY", $key, "User")
$env:FILE_ENCRYPTION_KEY = $key
```

Back up this secret somewhere safe. Encrypted uploads cannot be recovered if the key is lost or changed. Do not generate a new key after files have been uploaded. In each new PowerShell terminal that starts Django, load the saved key before running the server:

```powershell
$env:FILE_ENCRYPTION_KEY = [Environment]::GetEnvironmentVariable("FILE_ENCRYPTION_KEY", "User")
if (-not $env:FILE_ENCRYPTION_KEY) { throw "FILE_ENCRYPTION_KEY is not saved for this Windows user." }
```

In one terminal, start the API:

```powershell
cd backend
..\backend\venv\Scripts\python.exe manage.py migrate
..\backend\venv\Scripts\python.exe manage.py runserver 0.0.0.0:8000
```

In another terminal, install and start the frontend:

```powershell
cd frontend
npm ci
npm run dev
```

The UI is at `http://localhost:5173`. Root-level `npm run dev`, `npm run build`, and `npm run lint` commands are also available.

The browser keeps login tokens only for the current tab session. Refreshing the page keeps the user signed in, but closing the tab or browser clears the tokens; opening SV again requires logging in. Dashboard documents, shares, and activity refresh automatically every 15 seconds while the page is visible; use **Refresh** to update immediately.

## Upload a file

1. Start the Django API and the Vite frontend in separate terminals as described above. If you see an unapplied-migrations warning, stop Django and run `python manage.py migrate` from the `backend` folder.
2. Open `http://localhost:5173`, register an account, and log in.
3. On the dashboard, choose a file in **Secure Vault Upload**. Files larger than 100 MiB are rejected.

If upload fails, check the error displayed on the dashboard and the Django terminal. An encryption configuration message means the API terminal does not have `FILE_ENCRYPTION_KEY` set; load the saved key in that same terminal and restart Django. A 400 response usually means the file exceeds the limit or a required field is missing. For LAN use, follow the LAN setup steps below.

## Share and download files

1. Set a six-digit PIN for the file using the **Set PIN** field on your file. The PIN is stored as a password hash and is never shown again by SV; remember it.
2. The recipient must first register for an SV account. Ask them for their exact username.
3. Enter their username in the share form under your file. Its single optional end date/time applies only to that recipient; leave it blank for access that remains active until you revoke it.
4. Give the recipient the PIN separately, preferably through a different communication channel from their SV account credentials.
5. The recipient logs in, finds the file under **Shared with me**, enters the PIN, and clicks **Download**.
6. Choose **View / download** or **Edit and replace the original** when sharing. You can change an existing recipient's role by sharing with the same username again and selecting the new role.
7. To stop access, click **Revoke** beside that recipient under the file. Revocation and expiry are checked on the next request to any protected file route.

The share form's optional expiry is per recipient. At its deadline, that recipient's grant expires while the owner retains the original and other recipients keep their separate grants. The server checks expiry on every shared-file route. There is no separate file-wide expiry setting.

Shared files are not public links: recipients must be signed in to the invited account and know the file PIN. Five incorrect PIN attempts lock that share for 15 minutes. The owner can change a PIN at any time; removing the PIN revokes all active shares for that file. View access only permits downloading. When the owner grants Edit access, that recipient can submit a replacement after entering the PIN; changing the share to View or revoking it removes that ability. A replacement updates the original for the owner and all recipients, and the previous encrypted file is removed. The recipient must download and edit the file outside SV before uploading its replacement. File interactions, downloads, failed PIN attempts, denied access, and permission changes are recorded in the audit trail, which staff and the relevant file owner can view. Share revocation is checked by the server on each request; it cannot retract data already downloaded or a response already in progress.

The audit log is HMAC-signed and hash-chained, with a matching event checkpoint written to a separate persistent volume in Docker. In production, set `AUDIT_LOG_HMAC_KEY` to a separate, high-entropy secret, preserve it securely, and keep it unchanged for the lifetime of the existing audit history. After migration, verify both records with:

```powershell
cd backend
..\backend\venv\Scripts\python.exe manage.py verify_audit_chain
```

For Docker, run `docker compose exec backend python manage.py verify_audit_chain`. Read [THREATS.md](./THREATS.md) for the threat model, test coverage, key-handling requirements, and accepted limitations. The HMAC chain plus separate checkpoint detect database-only edits when verified; they cannot protect evidence from an attacker controlling the application host or its signing key. Export audit data and verification checkpoints to independently controlled append-only storage for stronger evidence.

## Use from another device on your LAN

1. Find the server computer's private IPv4 address (for example, `192.168.1.25`).
2. Start Django on the server computer at `127.0.0.1:8000` as shown above, then start Vite with `npm run dev`. Vite serves the frontend on the network and proxies `/api/` requests to Django on the same computer, so other devices use the frontend's address for both login and API calls.
3. Open `http://192.168.1.25:5173` on the other device. If Windows Firewall prompts when Vite starts, allow it only on your private network. If no prompt appears and the page cannot be reached, an administrator can allow inbound TCP port 5173 on the private profile:

   ```powershell
   New-NetFirewallRule -DisplayName "SV LAN frontend" -Direction Inbound -Protocol TCP -LocalPort 5173 -Action Allow -Profile Private
   ```

Do not expose the Vite development server to the public internet. This setup is for devices on the same trusted local network. For access from other networks, use the HTTPS Docker deployment below with a public domain and host; a private LAN address cannot be accessed over the internet.

The frontend uses same-origin `/api/` requests by default. In LAN development, Vite proxies these requests to Django. In production, Caddy routes them directly to the API. For a separately hosted API, set `VITE_API_BASE_URL` to its full API URL (including `/api/`) before building and configure the API's allowed CORS origin.

## Database and production configuration

SQLite is the default and is suitable for a single server with local persistent storage. For PostgreSQL, set `DATABASE_ENGINE=django.db.backends.postgresql` and configure `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`, `DATABASE_HOST`, and `DATABASE_PORT`.

For production, set `DJANGO_DEBUG=false`, a unique `DJANGO_SECRET_KEY`, `FILE_ENCRYPTION_KEY`, and comma-separated `DJANGO_ALLOWED_HOSTS`, `CORS_ALLOWED_ORIGINS`, and (for the Django admin over HTTPS) `CSRF_TRUSTED_ORIGINS`; serve the site and API over HTTPS. Set `DJANGO_SECURE_SSL_REDIRECT=false` only when HTTPS is terminated by a trusted reverse proxy that handles redirects itself. Enable `SECURE_HSTS_INCLUDE_SUBDOMAINS` or `SECURE_HSTS_PRELOAD` only if every affected subdomain is permanently HTTPS-only. Use persistent shared storage for uploaded files and keep the same encryption key across all application instances. Back up the database, encrypted file storage, and encryption key together.

Existing files from before the encryption update are marked **Legacy plaintext** and remain downloadable for compatibility; upload them again to store an encrypted copy. New files are encrypted before being written to storage. File data is never served through a public media URL.

### Single-server HTTPS deployment with Docker

The included Compose setup runs PostgreSQL, Django/Gunicorn, the built React app, and Caddy for automatic HTTPS. It is deployment configuration, not a hosted service: you need a Linux host with Docker Compose, a domain whose DNS points to that host, and inbound TCP ports 80 and 443 open.

1. Copy `.env.example` to `.env` (`cp .env.example .env` on Linux/macOS, or `Copy-Item .env.example .env` in PowerShell) and set `DOMAIN` to your public hostname. Set `DJANGO_ALLOWED_HOSTS` to that hostname and `CSRF_TRUSTED_ORIGINS` to `https://` followed by that hostname.
2. Generate independent secrets and set them in `.env`. Run these commands from the project root; save each output under the matching name:

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(50))"
   python -c "import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

   The outputs are `DJANGO_SECRET_KEY`, `FILE_ENCRYPTION_KEY`, and `AUDIT_LOG_HMAC_KEY`, respectively. The commands use Python's standard library. Keep all secrets safe; never regenerate the file-encryption or audit HMAC key for an installation containing data or audit history.
3. Set a long, unique `DATABASE_PASSWORD`, then start the services:

   ```powershell
   docker compose up --build -d
   docker compose logs -f
   ```

   The backend applies migrations and collects Django admin static files at startup. Caddy obtains and renews the HTTPS certificate after the domain resolves publicly.
4. Create the initial administrator using the backend container. Choose a unique password; SV does not ship with a predefined administrator username or password. In PowerShell, enter the credentials into the current session, then create the account:

   ```powershell
   $env:SV_ADMIN_USERNAME = Read-Host "Administrator username"
   $env:SV_ADMIN_EMAIL = Read-Host "Administrator email"
   $securePassword = Read-Host "Administrator password" -AsSecureString
   $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
   try {
       $env:SV_ADMIN_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
       docker compose run --rm --no-deps -e SV_ADMIN_USERNAME -e SV_ADMIN_EMAIL -e SV_ADMIN_PASSWORD backend python manage.py bootstrap_admin
   } finally {
       [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
       Remove-Item Env:\SV_ADMIN_USERNAME, Env:\SV_ADMIN_EMAIL, Env:\SV_ADMIN_PASSWORD -ErrorAction SilentlyContinue
   }
   ```

   The command requires all three values, validates the password with Django's configured validators, creates a superuser only when that username does not already exist, and never prints the password. Keep the password out of source control and clear the temporary shell variables after use. For local development, set the same three environment variables in the terminal running `python manage.py bootstrap_admin`. The SV staff portal is available at `https://your-domain/control`; the Django admin is at `https://your-domain/admin/`. Staff can manage all documents and moderate ordinary accounts from the SV portal. Deleting a document also removes its shares and edited copies but preserves its audit history.

PostgreSQL, encrypted uploads, and audit checkpoints are stored in named Docker volumes. Back up those volumes along with the exact encryption key, audit HMAC key, and Django secret; do not remove volumes when upgrading. Keep `.env` private. This setup targets a single host and does not provide multi-region storage, high availability, or managed backups. Dashboard logout calls the server to invalidate all of that account's existing access and refresh tokens, so it signs the user out on other devices too; password changes also invalidate existing tokens.

## Checks

```powershell
cd backend
..\backend\venv\Scripts\python.exe manage.py check
..\backend\venv\Scripts\python.exe manage.py test
cd ..\frontend
npm run lint
npm run build
```

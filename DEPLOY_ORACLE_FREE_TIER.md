# Oracle Cloud Free Tier + DuckDNS deployment checklist

This checklist is for a **fresh** single-host SV deployment on an OCI Ubuntu
ARM64 Ampere A1 VM. It follows the existing Docker Compose setup: PostgreSQL,
Django/Gunicorn, React/Nginx, and Caddy. Do not copy the local SQLite database,
uploads, or audit checkpoint; the local audit chain is known to fail
verification at event 63.

This setup is best-effort free-tier hosting, not high availability or a
service-level guarantee. OCI A1 capacity, home-region eligibility, and free
limits can change; idle Always Free instances may be reclaimed. Check the
current OCI console and billing/usage alerts before provisioning.

## 1. Prepare accounts and access

- [ ] Create/verify an OCI account and choose its home region carefully. Always
      Free A1 must be created in the home region. Select the closest available
      region for users/data-residency needs; confirm A1 capacity before
      proceeding. Out-of-capacity errors may require waiting or another
      availability domain in that home region.
- [ ] Create a DuckDNS account and choose a unique subdomain, such as
      `your-sv-name.duckdns.org`. Keep its update token private.
- [ ] Generate an SSH key pair locally. Add only its public key to OCI; never
      upload or send the private key.
- [ ] Decide where encrypted off-VM backups will live before storing important
      files. A backup on the VM's own disk is not a disaster-recovery backup.

OCI documents a shared Always Free A1 allowance (up to 2 OCPUs and 12 GB
memory-equivalent monthly allowance, subject to eligibility/limits). Confirm
the current size and estimate in the console. Use Ubuntu ARM64. Start with
1–2 OCPUs and memory adequate for Postgres, Django, and Caddy; a small VM may
struggle building containers. The project's base images support ARM64. Boot
volume and other storage consume the tenancy's block-volume allowance.

## 2. Create and secure the VM

- [ ] Create an A1 Flex VM in your home region and a public subnet. Assign a
      public IPv4 address; reserve a static IP if available within your free
      allowance, otherwise expect to update DuckDNS if it changes.
- [ ] Add stateful OCI ingress rules:
  - TCP 22 only from your trusted current public IP/CIDR.
  - TCP 80 from the internet for HTTP redirect and ACME validation.
  - TCP 443 from the internet for HTTPS.
  - Optional UDP 443 for HTTP/3.
- [ ] Do not expose ports 5432 (PostgreSQL), 8000 (Django), or the frontend
      container port. Compose publishes only Caddy's public ports.
- [ ] SSH in with the private key. Apply OS security updates and use a
      non-root sudo account. Disable password SSH only after confirming
      key-based access in another terminal. Keep SSH ingress restricted.
- [ ] Install Docker Engine and the Compose plugin using Docker's official
      Ubuntu guide. Confirm `docker compose version`.
- [ ] Create an application directory such as `/opt/sv`. Configure host
      firewall rules carefully: OCI network rules are primary, and Docker
      published ports can interact unexpectedly with host firewall rules.

## 3. Configure DuckDNS and TLS prerequisites

- [ ] Point the DuckDNS A record to the VM's current public IPv4. Do not set an
      AAAA record unless public IPv6 routing and firewall rules are configured.
- [ ] Confirm from outside the VM that DNS resolves to the current address.
- [ ] Run a supervised DuckDNS update script/service to update the A record
      after address changes. Store its token in a root-readable-only config
      file (for example permissions `0600`), not in Git, shell history,
      container images, or logs.
- [ ] Confirm inbound TCP 80/443 reach the VM and are not blocked or already
      used by another service. Caddy requires a public hostname resolving to
      the server and reachable ports to obtain/renew public certificates.
- [ ] Keep Caddy's `/data` and `/config` volumes persistent so certificate
      state survives container replacement.

DuckDNS is a dynamic DNS subdomain, not a custom registered domain. Check its
current terms, availability, and update instructions before relying on it.

## 4. Configure SV with fresh production secrets

- [ ] Copy first-party source files to `/opt/sv` through secure transfer.
      Exclude `.env`, `backend/db.sqlite3`, `backend/media`, audit checkpoint,
      `backend/venv`, `node_modules`, and build output.
- [ ] Copy `.env.example` to `.env`, protect it (for example `chmod 600 .env`),
      and set:

  | Variable | Required value |
  | --- | --- |
  | `DOMAIN` | Exact DuckDNS hostname, no scheme or path |
  | `DJANGO_SECRET_KEY` | New unique high-entropy secret |
  | `AUDIT_LOG_HMAC_KEY` | Separate high-entropy key, distinct from Django key |
  | `FILE_ENCRYPTION_KEY` | URL-safe base64 key that decodes to exactly 32 bytes |
  | `DJANGO_ALLOWED_HOSTS` | Exact hostname |
  | `CSRF_TRUSTED_ORIGINS` | `https://` plus exact hostname |
  | `CORS_ALLOWED_ORIGINS` | Blank for same-origin frontend/API deployment |
  | `DATABASE_NAME`, `DATABASE_USER` | Unique production values |
  | `DATABASE_PASSWORD` | Long randomly generated secret |
  | `GUNICORN_WORKERS` | Start at 2; reduce if memory pressure occurs |
  | `MAX_FILE_UPLOAD_SIZE` | 104857600 (100 MiB) unless storage/backups justify otherwise |

- [ ] Generate independent secrets on the VM or a trusted local machine; enter
      them directly into the protected `.env`, not into Git or chat:

  ```sh
  python3 -c 'import secrets; print(secrets.token_urlsafe(50))'
  python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'
  python3 -c 'import secrets; print(secrets.token_hex(32))'
  ```

  Use the outputs for Django, file encryption, and audit HMAC keys,
  respectively, and generate a different database password. Back up exact
  keys securely. Never regenerate file-encryption or audit keys after data is
  stored.

- [ ] Check `.gitignore` and Docker ignore files. No `.env`, tokens, private
      keys, database dumps, media, or backups should enter Git or build
      contexts.
- [ ] Validate configuration and build:

  ```sh
  docker compose config --quiet
  docker compose build
  ```

## 5. Start and verify the site

- [ ] Start services and inspect health/logs:

  ```sh
  docker compose up --build -d
  docker compose ps
  docker compose logs --tail=100 backend caddy
  ```

- [ ] Wait for PostgreSQL and backend health checks. Backend startup applies
      migrations and collects static assets before running Gunicorn.
- [ ] Create the initial admin using `python manage.py bootstrap_admin` via a
      one-off backend container. Prompt for credentials; pass environment
      variable names, not values, to `docker compose run`. Clear temporary
      shell variables afterward. Never put credentials in the image or source.
- [ ] Open `https://<duckdns-hostname>/`; confirm the browser trusts the TLS
      certificate. Test registration/sign-in with a disposable user and ensure
      that user cannot access `/control`.
- [ ] End-to-end test disposable files: upload, set PIN, share with a second
      test account, correct/incorrect PIN, download, revoke/expiry, Edit
      replacement, and an admin operation. Clean up the test data afterward.
- [ ] From an external network, verify only trusted-IP SSH and public TCP 80/443
      (plus optional UDP 443) are reachable. Confirm 5432, 8000, and frontend
      ports are not public.
- [ ] Verify production configuration:

  ```sh
  docker compose exec backend python manage.py check --deploy
  docker compose exec backend python manage.py verify_audit_chain
  ```

  A fresh audit chain should verify before real data is accepted. Django may
  show optional HSTS subdomain/preload warnings. Enable those only if every
  affected hostname is permanently HTTPS-only and preload is an intentional
  commitment.

## 6. Backups and recovery

- [ ] Schedule consistent PostgreSQL dumps and encrypted-media backups.
      Preserve the audit checkpoint with the matching database backup.
- [ ] Copy backups off the VM, encrypt them before transfer, and test a restore
      in an isolated environment.
- [ ] Back up `.env` secrets separately in an encrypted secret store/password
      manager. Database/media backups without `FILE_ENCRYPTION_KEY` cannot
      recover encrypted document bytes.
- [ ] Preserve the audit HMAC key and its checkpoint; losing/changing the key
      makes existing signatures unverifiable.
- [ ] Document VM rebuild, service restoration, volume recovery, secret
      restoration, and DuckDNS update steps.
- [ ] Monitor free compute and disk usage, container restarts, DNS updater
      failures, Caddy certificate logs, and OCI billing/usage alerts.

## Constraints

- This is a single-server setup; it has no built-in managed backups,
  multi-region failover, or independent audit replication.
- A1 is ARM64. If using a remote build host, verify the image architecture;
  building directly on the A1 VM avoids accidental x86-only images.
- DuckDNS update failure after an IP change breaks DNS and may interrupt
  certificate renewal.
- Free-tier availability and eligibility are controlled by OCI and can
  change. Do not treat free infrastructure as an SLA.
- Keep local data separate; the local audit chain fails verification at event
  63. This checklist starts with clean production volumes and does not migrate
  local users, documents, or audit records.

## Official references

- [OCI Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
- [OCI security lists](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securitylists.htm)
- [DuckDNS](https://www.duckdns.org/)
- [DuckDNS update specification](https://www.duckdns.org/spec.jsp)
- [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https)
- [Docker Engine installation on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

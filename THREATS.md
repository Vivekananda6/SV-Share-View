# SV threat model and security decisions

This document records the threats considered for the current SV codebase and
the protections and limitations that are actually implemented. It is not a claim
that a deployed host is invulnerable. Re-run the listed checks against the exact
deployment and configuration before accepting files containing sensitive data.

## Protected assets and security boundaries

- Document bytes, names, categories, ownership, shares, PIN state, and revisions.
- Account credentials, access tokens, and refresh tokens.
- Audit events, including refused access attempts.
- The encryption key, Django signing secret, and audit HMAC key.

The Django API is the authorization boundary. React controls are usability only.
Every document API request must be authenticated and must pass an owner- or
active-share-scoped server-side query. Docker production routes API, admin, static,
and media paths through Caddy. Media is deliberately not served by Django or
Nginx; Caddy sends `/media/` probes to Django so the deny middleware can record
them.

## Threats and mitigations

| Threat / attack path | Protection in the code | Regression tests / verification |
| --- | --- | --- |
| Guess or reuse another owner's document ID against list, detail, download, update, delete, passcode, sharing, or revision actions. | Owner endpoints start from `SecureFile.objects.filter(user=request.user)`; IDs do not authorize access. Every protected route checks the authenticated server-side user. | `test_unshared_user_cannot_read_download_change_or_delete_document`; `test_user_cannot_download_another_users_file`. |
| Exploit administrator document controls as an ordinary account or conceal staff access to a document. | Global document listing, downloads, replacement, metadata edits, share revocation, and deletion are gated by Django's server-side `IsAdminUser` permission. File operations record the staff actor and document owner/title in the audit chain. Admins intentionally bypass owner/recipient PIN checks. | `test_staff_can_manage_every_document_and_revoke_any_share` verifies staff access and that a non-staff account is denied; it also checks the download audit event. |
| Call shared-file detail, revisions, replacement, or download endpoints directly, bypassing dashboard controls. | Recipient endpoints resolve only active shares for the logged-in recipient. Replacement additionally requires the owner's `edit` grant and the PIN. Revision downloads are restricted to the owner or the editor who uploaded that revision with an active Edit share. | `test_unshared_user_cannot_read_download_change_or_delete_document`; `test_owner_grants_and_revokes_original_replacement_through_share_permission`; `test_owner_can_share_file_with_registered_user_for_download`. |
| Reuse an ID after the owner revokes or expires a share; retain access through a separate endpoint. | Active-share filtering is evaluated on each request (including details, revisions, replacement, and downloads). Revocation and expiry do not rely on cached frontend state. | `test_owner_can_revoke_share_and_recipient_loses_access`; `test_expired_share_cannot_be_accessed_through_any_route`. |
| Download an uploaded object by constructing a `/media/...` URL, including legacy plaintext files. | No media URL is configured as a public file server. Production Caddy routes media probes to Django, where the middleware returns the framework's not-found response and records the attempt. | `test_direct_media_urls_do_not_serve_files_and_are_audited`. |
| Reuse a copied access or refresh token after logout, or use one after a password change. | Tokens carry a per-account version checked on every access-token authentication and refresh. Logout increments the version, invalidating all of that account's sessions; password-hash claims also invalidate tokens after password changes. | `test_jwt_login_refresh_and_authenticated_api`. |
| Access data after account deactivation. | JWT authentication checks that the account is active for each authenticated request. | `test_inactive_user_tokens_are_rejected`. |
| Hide a denied request by using invalid IDs, a different HTTP method, an unauthenticated request, or an admin route. | The DRF exception handler records 401, 403, 404, 405, and 429 denials with method, path, actor when known, remote address, outcome, and related document where resolvable. Django's failed-login signal records rejected login names without passwords; middleware records denied admin and direct-media paths. Explicit PIN/share failures are also audited. | `test_unauthenticated_denials_are_audited`; `test_unshared_user_cannot_read_download_change_or_delete_document`; `test_owner_can_set_change_and_remove_passcode`; `test_incorrect_passcode_locks_share_after_five_attempts`; `test_direct_media_urls_do_not_serve_files_and_are_audited`; `test_failed_login_is_audited_without_recording_password`; `test_staff_can_view_audit_admin_and_users_cannot`. |
| Alter an audit row, remove an event, reorder history, or silently truncate the audit tail using database-only access. | Each event includes an HMAC-SHA256 signature over its recorded fields and the previous event hash. A separate append-only-in-normal-operation checkpoint file records every event ID/hash on a named volume mounted only in the backend, not the database container. Production requires a separately configured `AUDIT_LOG_HMAC_KEY`. Admin/API audit views are read-only. Verify both histories with `python manage.py verify_audit_chain` (or `docker compose exec backend python manage.py verify_audit_chain`). | `test_audit_chain_detects_tampered_records`; `test_external_checkpoint_detects_database_tail_truncation`; `test_staff_can_view_audit_admin_and_users_cannot`; `test_superuser_can_delete_file_and_copies_without_deleting_audit`. |
| Brute-force the six-digit file PIN through a valid share. | Attempts are counted per share and locked for 15 minutes after five failures. The PIN is password-hashed and required for each recipient download or replacement; it is not returned by the API. | `test_incorrect_passcode_locks_share_after_five_attempts`; `test_owner_can_set_change_and_remove_passcode`. |
| Upload an empty, overlong-name, or oversized file, or replace a file with invalid content size. | Upload and replacement serializers reject empty files, names over 255 characters, and files over the configured size. Files are encrypted before storage; arbitrary legitimate document formats remain supported. | `test_upload_enforces_file_size_limit`; `test_upload_rejects_empty_file`; `test_replacing_file_keeps_storage_encrypted`. |
| Obtain a file through an unapproved edit permission or treat Edit as a general account role. | Edit is per named recipient and per document. The owner chooses View or Edit and can downgrade or revoke the grant; staff approval is not in this workflow. | `test_owner_grants_and_revokes_original_replacement_through_share_permission`. |
| Forge a source IP using an arbitrary client-supplied forwarding header. | The audit row records Django's immediate peer address; do not treat arbitrary forwarded headers as identity. Caddy also emits JSON access logs to stdout, including the network peer, for collection by the host. | Review Caddy logs together with the application audit chain for investigations. |
| Misread an all-time activity count or fail to find older account/document entries hidden by a sample limit. | The activity metric is explicitly a rolling 24-hour count from the database; its trail is the latest 50 relevant events. Admin account and document listings are paginated, global counts are not page-limited, and event search operates server-side. | `test_activity_summary_counts_exactly_the_last_24_hours`; `test_admin_portal_is_staff_only_and_reports_platform_metrics`; `test_staff_can_manage_every_document_and_revoke_any_share`. |

## Accepted risks and operational assumptions

1. **A compromised application host or trusted operator can defeat local evidence.**
   The backend must read `AUDIT_LOG_HMAC_KEY` to create signatures. Someone controlling
   the running process, host environment, or deployment secret can read that key and
   can create valid forged records or rewrite the checkpoint volume. The separate
   volume is intended to make database-only edits detectable, not to defend against
   root on the application host. For stronger evidence, export audit events and
   periodic chain-head checkpoints to an independently administered append-only/WORM
   log service. SV does not currently provision that external service.
2. **The chain is not an external timestamp authority.** Run `verify_audit_chain`
   routinely and preserve its output and checkpoints independently of the database.
   If the HMAC key is lost or changed, existing records will no longer verify. Back it
   up separately
   and never rotate it without a planned, independently recorded migration.
   The current local database fails verification at audit event 63: its stored event
   hash matches the checkpoint, but its HMAC does not validate. The cause is unknown.
   Treat the affected history as unverified, preserve the database, checkpoint, and
   signing key for investigation, and do not silently edit or re-sign the historical
   event. This finding is specific to the current local audit data, not a repair made
   by the application changes.
3. **An unauthenticated caller has no verified account identity.** Such attempts are
   recorded with route, outcome, and the immediate network peer. Behind Docker/Caddy,
   Django's peer can be the proxy; correlate with Caddy's access logs to identify the
   connecting address. A direct-media request with a valid bearer token is attributed
   to that account; an unauthenticated caller is attributed only to the network peer.
   An IP address is not proof of a human identity and can represent NAT/shared networks.
4. **Revocation is prospective, not retroactive.** It blocks the next server request.
   It cannot recall plaintext already downloaded, a screenshot/copy, or bytes already
   sent on an in-progress response. Recipients with Edit can replace the owner-shared
   original while that grant remains active; the owner must downgrade or revoke access
   first to stop future replacements.
5. **Application-level encryption does not protect against the live backend host.**
   The backend holds the AES-256-GCM key and can decrypt files to serve an authorized
   download. Anyone controlling that process, host, or encryption secret can read the
   stored data. Protect backups, database credentials, media volumes, and secrets.
6. **Single-server deployment and availability are outside this authorization
   guarantee.** Database, host, storage, or network failure can make the service
   unavailable. The project does not currently provide independent audit replication,
   multi-region failover, or managed backups.
7. **Checkpoint storage failure can interrupt evidence collection.** Audit writes
   flush the checkpoint to persistent storage and surface write errors; they do not
   report a successful audited response when that write fails. A mutation may already
   have reached the database or file store before its audit write is attempted, so
   reconcile any API error with the database, file storage, Caddy logs, and checkpoint
   verifier before retrying.

## Release checks

Before deploying, run backend tests, Django system checks, migration consistency,
frontend lint/build, and the audit verifier. Confirm that production has `DEBUG=false`,
HTTPS, a unique `DJANGO_SECRET_KEY`, the same persistent `FILE_ENCRYPTION_KEY` used for
existing files, and a distinct high-entropy `AUDIT_LOG_HMAC_KEY`. Do not expose the
backend or media storage as a public file server.

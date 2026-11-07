import base64
import os
import tempfile
from datetime import timedelta
from pathlib import Path

from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command, CommandError
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone
from unittest.mock import patch
from rest_framework.test import APIClient

from .audit_integrity import verify_audit_chain
from .crypto import MAGIC
from .models import (
    AuditChainState,
    AuditLog,
    AuthTokenVersion,
    FileShare,
    SecureFile,
    SharedFileRevision,
    UserModeration,
)
from .views import record_audit

TEST_ENCRYPTION_KEY = base64.urlsafe_b64encode(b"t" * 32).decode("ascii")


@override_settings(FILE_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY)
class SecureFileApiTests(TestCase):
    def setUp(self):
        self.media_dir = tempfile.TemporaryDirectory()
        self.media_settings = override_settings(MEDIA_ROOT=self.media_dir.name)
        self.media_settings.enable()
        self.audit_checkpoint_path = Path(self.media_dir.name) / "audit-checkpoint.jsonl"
        self.audit_settings = override_settings(
            AUDIT_CHECKPOINT_PATH=str(self.audit_checkpoint_path)
        )
        self.audit_settings.enable()
        self.audit_checkpoint_path.touch()

        self.client = APIClient()
        self.user = User.objects.create_user(username="alice", password="test-password")
        self.client.force_authenticate(user=self.user)

    def tearDown(self):
        self.audit_settings.disable()
        self.media_settings.disable()
        self.media_dir.cleanup()

    def test_upload_encrypts_file_and_download_returns_original(self):
        original_content = b"private file contents"
        upload = SimpleUploadedFile("private.txt", original_content, content_type="text/plain")
        response = self.client.post(
            "/api/files/",
            {"title": "private.txt", "category": "Reports", "file": upload},
            format="multipart",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["category"], "Reports")
        self.assertNotIn("file", response.data)
        secure_file = SecureFile.objects.get(pk=response.data["id"])
        self.assertEqual(secure_file.encryption_algorithm, "AES-256-GCM")
        self.assertEqual(secure_file.encryption_version, 1)
        self.assertEqual(secure_file.file_size, len(original_content))

        with secure_file.file.open("rb") as stored_file:
            ciphertext = stored_file.read()
        self.assertTrue(ciphertext.startswith(MAGIC))
        self.assertNotIn(original_content, ciphertext)

        download = self.client.get(f"/api/files/{secure_file.pk}/download/")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(b"".join(download.streaming_content), original_content)

    def test_user_cannot_download_another_users_file(self):
        owner = User.objects.create_user(username="bob", password="test-password")
        secure_file = SecureFile.objects.create(
            user=owner,
            title="private.txt",
            file=SimpleUploadedFile("private.txt", b"private"),
            file_size=7,
        )

        response = self.client.get(f"/api/files/{secure_file.pk}/download/")
        self.assertEqual(response.status_code, 404)
        owner_client = APIClient()
        owner_client.force_authenticate(user=owner)
        event = next(
            event for event in owner_client.get("/api/logs/").data
            if event["action"] == "File Access Denied"
        )
        self.assertEqual(event["action"], "File Access Denied")
        self.assertEqual(event["username"], "alice")
        self.assertEqual(event["file_title"], "private.txt")
        self.assertEqual(event["outcome"], "failure")

    def test_unshared_user_cannot_read_download_change_or_delete_document(self):
        owner = User.objects.create_user(username="bob")
        secure_file = SecureFile.objects.create(
            user=owner,
            title="private.txt",
            category="Contracts",
            file=SimpleUploadedFile("private.txt", b"private"),
            file_size=7,
        )
        url = f"/api/files/{secure_file.pk}/"

        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.get(f"{url}download/").status_code, 404)
        self.assertEqual(
            self.client.patch(url, {"category": "Public"}, format="json").status_code,
            404,
        )
        self.assertEqual(self.client.delete(url).status_code, 404)
        secure_file.refresh_from_db()
        self.assertEqual(secure_file.category, "Contracts")
        self.assertEqual(AuditLog.objects.filter(action="File Access Denied").count(), 4)

        recipient = User.objects.create_user(username="charlie")
        share = FileShare.objects.create(file=secure_file, recipient=recipient)
        FileShare.objects.create(
            file=secure_file,
            recipient=self.user,
            permission=FileShare.Permission.EDIT,
        )
        revision = SharedFileRevision.objects.create(
            source_file=secure_file,
            share=share,
            editor=recipient,
            title="revision.txt",
            file=SimpleUploadedFile("revision.txt", b"private revision"),
            file_size=16,
        )
        denied_routes = (
            ("GET", f"/api/shared-with-me/{share.pk}/"),
            ("GET", f"/api/shared-with-me/{share.pk}/revisions/"),
            ("POST", f"/api/shared-with-me/{share.pk}/replace/"),
            ("GET", f"/api/revisions/{revision.pk}/download/"),
        )
        for method, route in denied_routes:
            response = getattr(self.client, method.lower())(route)
            self.assertEqual(response.status_code, 404, route)
            self.assertTrue(
                AuditLog.objects.filter(
                    action="API Access Denied",
                    user=self.user,
                    file_owner=owner,
                    details__contains=route,
                ).exists(),
                route,
            )

    def test_direct_media_urls_do_not_serve_files_and_are_audited(self):
        owner = User.objects.create_user(username="bob")
        secure_file = SecureFile.objects.create(
            user=owner,
            title="legacy-private.txt",
            file=SimpleUploadedFile("legacy-private.txt", b"legacy secret"),
            file_size=13,
            encryption_algorithm="Legacy plaintext",
            encryption_version=0,
        )
        self.client.force_authenticate(user=None)
        login = self.client.post(
            "/api/token/",
            {"username": "alice", "password": "test-password"},
            format="json",
        )
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {login.data['access']}"
        )

        response = self.client.get(secure_file.file.url)

        self.assertEqual(response.status_code, 404)
        self.assertNotIn(b"legacy secret", response.content)
        self.assertTrue(
            AuditLog.objects.filter(
                action="Direct Media Access Denied",
                user=self.user,
                file=secure_file,
                outcome=AuditLog.Outcome.FAILURE,
            ).exists(),
        )

    def test_owner_can_organize_documents_and_search_authorized_documents(self):
        reports = SecureFile.objects.create(
            user=self.user,
            title="Quarterly report.pdf",
            category="Reports",
            file=SimpleUploadedFile("report.pdf", b"report"),
            file_size=6,
        )
        contracts = SecureFile.objects.create(
            user=self.user,
            title="Contract.pdf",
            category="Contracts",
            file=SimpleUploadedFile("contract.pdf", b"contract"),
            file_size=8,
        )
        SecureFile.objects.filter(pk=reports.pk).update(
            uploaded_at=timezone.now() - timedelta(days=10)
        )
        SecureFile.objects.filter(pk=contracts.pk).update(uploaded_at=timezone.now())

        updated = self.client.patch(
            f"/api/files/{contracts.pk}/",
            {"title": "Executed Contract.pdf", "category": "Legal"},
            format="json",
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.data["category"], "Legal")
        self.assertTrue(
            AuditLog.objects.filter(
                action="Document Metadata Updated",
                details__contains="category",
                file_title="Executed Contract.pdf",
            ).exists()
        )

        recipient = User.objects.create_user(username="bob")
        shared = SecureFile.objects.create(
            user=recipient,
            title="Shared report.pdf",
            category="Reports",
            file=SimpleUploadedFile("shared-report.pdf", b"shared"),
            file_size=6,
        )
        FileShare.objects.create(
            file=shared,
            recipient=self.user,
            permission=FileShare.Permission.VIEW,
        )

        owner_filter = self.client.get("/api/files/?owner=ali&category=Reports")
        self.assertEqual([item["id"] for item in owner_filter.data], [reports.pk])
        name_search = self.client.get("/api/files/?search=executed")
        self.assertEqual([item["id"] for item in name_search.data], [contracts.pk])
        date_filter = self.client.get(
            f"/api/files/?date_from={timezone.localdate().isoformat()}&category=Legal"
        )
        self.assertEqual([item["id"] for item in date_filter.data], [contracts.pk])
        invalid_date = self.client.get("/api/files/?date_from=not-a-date")
        self.assertEqual(invalid_date.status_code, 400)
        invalid_calendar_date = self.client.get("/api/files/?date_to=2026-99-99")
        self.assertEqual(invalid_calendar_date.status_code, 400)

        shared_search = self.client.get("/api/shared-with-me/?owner=bob&search=shared")
        self.assertEqual(shared_search.status_code, 200)
        self.assertEqual([item["file_id"] for item in shared_search.data], [shared.pk])
        self.assertEqual(shared_search.data[0]["category"], "Reports")

    def test_legacy_plaintext_file_remains_downloadable(self):
        secure_file = SecureFile.objects.create(
            user=self.user,
            title="legacy.txt",
            file=SimpleUploadedFile("legacy.txt", b"old contents"),
            file_size=12,
            encryption_algorithm="Legacy plaintext",
            encryption_version=0,
        )

        response = self.client.get(f"/api/files/{secure_file.pk}/download/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"old contents")

    def test_registration_validates_password_and_creates_user(self):
        self.client.force_authenticate(user=None)
        weak_password = self.client.post(
            "/api/register/",
            {"username": "new-user", "password": "password"},
            format="json",
        )
        self.assertEqual(weak_password.status_code, 400)
        self.assertFalse(User.objects.filter(username="new-user").exists())

        response = self.client.post(
            "/api/register/",
            {"username": "new-user", "password": "A-strong-example-Pass!738"},
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(User.objects.filter(username="new-user").exists())

    def test_client_cannot_choose_encryption_metadata(self):
        upload = SimpleUploadedFile("private.txt", b"private")
        response = self.client.post(
            "/api/files/",
            {
                "title": "private.txt",
                "file": upload,
                "encryption_algorithm": "none",
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, 201)
        secure_file = SecureFile.objects.get(pk=response.data["id"])
        self.assertEqual(secure_file.encryption_algorithm, "AES-256-GCM")

    @override_settings(MAX_FILE_UPLOAD_SIZE=3)
    def test_upload_enforces_file_size_limit(self):
        upload = SimpleUploadedFile("large.txt", b"four")
        response = self.client.post(
            "/api/files/",
            {"title": "large.txt", "file": upload},
            format="multipart",
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(SecureFile.objects.exists())

    def test_upload_rejects_empty_file(self):
        response = self.client.post(
            "/api/files/",
            {
                "title": "empty.txt",
                "file": SimpleUploadedFile("empty.txt", b""),
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["file"][0].code, "empty")
        self.assertFalse(SecureFile.objects.exists())

    @override_settings(FILE_ENCRYPTION_KEY="")
    def test_upload_reports_missing_encryption_configuration(self):
        response = self.client.post(
            "/api/files/",
            {
                "title": "private.txt",
                "file": SimpleUploadedFile("private.txt", b"private"),
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("FILE_ENCRYPTION_KEY", response.data["detail"])
        self.assertFalse(SecureFile.objects.exists())

    def test_replacing_file_keeps_storage_encrypted(self):
        original = self.client.post(
            "/api/files/",
            {
                "title": "replace.txt",
                "file": SimpleUploadedFile("replace.txt", b"original"),
            },
            format="multipart",
        )
        self.assertEqual(original.status_code, 201)
        original_file = SecureFile.objects.get(pk=original.data["id"])
        previous_path = original_file.file.path

        response = self.client.patch(
            f"/api/files/{original.data['id']}/",
            {"file": SimpleUploadedFile("replace.txt", b"replacement")},
            format="multipart",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["file_size"], len(b"replacement"), response.data)

        secure_file = SecureFile.objects.get(pk=original.data["id"])
        self.assertNotEqual(secure_file.file.path, previous_path)
        self.assertEqual(secure_file.encryption_version, 1)
        with secure_file.file.open("rb") as stored_file:
            self.assertTrue(stored_file.read().startswith(MAGIC))
        self.assertFalse(Path(previous_path).exists())

        download = self.client.get(f"/api/files/{secure_file.pk}/download/")
        self.assertEqual(b"".join(download.streaming_content), b"replacement")
        self.assertTrue(self.user.auditlog_set.filter(action="File Updated").exists())

    def test_deleting_file_removes_storage_and_records_activity(self):
        response = self.client.post(
            "/api/files/",
            {
                "title": "delete.txt",
                "file": SimpleUploadedFile("delete.txt", b"delete me"),
            },
            format="multipart",
        )
        secure_file = SecureFile.objects.get(pk=response.data["id"])
        stored_path = secure_file.file.path

        delete_response = self.client.delete(f"/api/files/{secure_file.pk}/")

        self.assertEqual(delete_response.status_code, 204)
        self.assertFalse(SecureFile.objects.filter(pk=secure_file.pk).exists())
        self.assertFalse(Path(stored_path).exists())
        self.assertTrue(
            self.user.auditlog_set.filter(action="File Deleted").exists()
        )

    def test_jwt_login_refresh_and_authenticated_api(self):
        self.client.force_authenticate(user=None)
        token_response = self.client.post(
            "/api/token/",
            {"username": "alice", "password": "test-password"},
            format="json",
        )
        self.assertEqual(token_response.status_code, 200)
        self.assertTrue(
            AuditLog.objects.filter(
                action="Login Succeeded",
                actor_username="alice",
                outcome=AuditLog.Outcome.SUCCESS,
            ).exists()
        )

        authenticated_client = APIClient()
        authenticated_client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {token_response.data['access']}"
        )
        files_response = authenticated_client.get("/api/files/")
        self.assertEqual(files_response.status_code, 200)

        refresh_response = authenticated_client.post(
            "/api/token/refresh/",
            {"refresh": token_response.data["refresh"]},
            format="json",
        )
        self.assertEqual(refresh_response.status_code, 200)

        logout_response = authenticated_client.post("/api/logout/")
        self.assertEqual(logout_response.status_code, 204)
        self.assertEqual(authenticated_client.get("/api/files/").status_code, 401)
        revoked_refresh = self.client.post(
            "/api/token/refresh/",
            {"refresh": token_response.data["refresh"]},
            format="json",
        )
        self.assertEqual(revoked_refresh.status_code, 401)
        self.assertTrue(
            AuditLog.objects.filter(
                action="Authentication Denied",
                actor_username="alice",
                outcome=AuditLog.Outcome.FAILURE,
            ).exists()
        )

        replacement_login = self.client.post(
            "/api/token/",
            {"username": "alice", "password": "test-password"},
            format="json",
        )
        authenticated_client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {replacement_login.data['access']}"
        )
        self.assertEqual(authenticated_client.get("/api/files/").status_code, 200)
        old_refresh = replacement_login.data["refresh"]
        self.user.set_password("changed-password")
        self.user.save(update_fields=["password"])
        self.assertEqual(authenticated_client.get("/api/files/").status_code, 401)
        self.assertEqual(
            self.client.post(
                "/api/token/refresh/",
                {"refresh": old_refresh},
                format="json",
            ).status_code,
            401,
        )

    def test_inactive_user_tokens_are_rejected(self):
        self.client.force_authenticate(user=None)
        tokens = self.client.post(
            "/api/token/",
            {"username": "alice", "password": "test-password"},
            format="json",
        )
        self.assertEqual(tokens.status_code, 200)
        authenticated_client = APIClient()
        authenticated_client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {tokens.data['access']}"
        )

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        self.assertEqual(authenticated_client.get("/api/files/").status_code, 401)
        self.assertEqual(
            self.client.post(
                "/api/token/refresh/",
                {"refresh": tokens.data["refresh"]},
                format="json",
            ).status_code,
            401,
        )
        self.assertTrue(
            AuditLog.objects.filter(
                action="Authentication Denied",
                actor_username="alice",
                outcome=AuditLog.Outcome.FAILURE,
            ).exists()
        )

    def test_unauthenticated_denials_are_audited(self):
        anonymous_client = APIClient()
        response = anonymous_client.get("/api/files/")

        self.assertEqual(response.status_code, 401)
        event = AuditLog.objects.get(
            action="API Access Denied",
            details__contains="GET /api/files/",
        )
        self.assertIsNone(event.user_id)
        self.assertEqual(event.outcome, AuditLog.Outcome.FAILURE)

    def test_audit_chain_detects_tampered_records(self):
        upload = self.client.post(
            "/api/files/",
            {
                "title": "integrity.txt",
                "file": SimpleUploadedFile("integrity.txt", b"evidence"),
            },
            format="multipart",
        )
        self.assertEqual(upload.status_code, 201)
        valid, message = verify_audit_chain()
        self.assertTrue(valid, message)
        serialized_event = next(
            event for event in self.client.get("/api/logs/").data
            if event["action"] == "File Uploaded"
        )
        self.assertEqual(len(serialized_event["integrity_hash"]), 64)
        self.assertEqual(len(serialized_event["previous_hash"]), 64)

        event = AuditLog.objects.get(action="File Uploaded")
        AuditLog.objects.filter(pk=event.pk).update(details="silently changed")
        valid, message = verify_audit_chain()
        self.assertFalse(valid)
        self.assertIn(str(event.pk), message)

    def test_external_checkpoint_detects_database_tail_truncation(self):
        response = self.client.post(
            "/api/files/",
            {
                "title": "checkpoint.txt",
                "file": SimpleUploadedFile("checkpoint.txt", b"checkpoint"),
            },
            format="multipart",
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(verify_audit_chain()[0])

        AuditLog.objects.all().delete()
        AuditChainState.objects.filter(pk=1).update(last_hash="0" * 64)
        valid, message = verify_audit_chain()

        self.assertFalse(valid)
        self.assertIn("checkpoint", message.lower())

    def test_failed_login_is_audited_without_recording_password(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(
            "/api/token/",
            {"username": "alice", "password": "incorrect-password"},
            format="json",
        )

        self.assertEqual(response.status_code, 401)
        event = AuditLog.objects.get(action="Login Failed")
        self.assertEqual(event.actor_username, "alice")
        self.assertEqual(event.outcome, AuditLog.Outcome.FAILURE)
        self.assertNotIn("incorrect-password", event.details)

    def test_owner_can_share_file_with_registered_user_for_download(self):
        uploaded = self.client.post(
            "/api/files/",
            {
                "title": "shared.txt",
                "file": SimpleUploadedFile("shared.txt", b"shared contents"),
            },
            format="multipart",
        )
        file_id = uploaded.data["id"]
        passcode_response = self.client.put(
            f"/api/files/{file_id}/passcode/",
            {'passcode': '123456'},
            format='json',
        )
        self.assertEqual(passcode_response.status_code, 200)
        self.assertTrue(passcode_response.data['has_passcode'])
        recipient = User.objects.create_user(username="bob", password="test-password")
        recipient_client = APIClient()
        recipient_client.force_authenticate(user=recipient)

        expires_at = (timezone.now() + timedelta(days=2)).isoformat()
        share_response = self.client.post(
            f"/api/files/{file_id}/share/",
            {"username": "bob", "expires_at": expires_at},
            format="json",
        )
        self.assertEqual(share_response.status_code, 201)
        self.assertTrue(
            AuditLog.objects.filter(
                action="File Shared",
                user=self.user,
                file_title="shared.txt",
            ).exists()
        )
        share_id = share_response.data["id"]
        self.assertEqual(share_response.data["username"], "bob")
        self.assertEqual(share_response.data["permission"], "view")
        self.assertTrue(share_response.data["active"])

        shared_files = recipient_client.get("/api/shared-with-me/")
        self.assertEqual(shared_files.status_code, 200)
        self.assertEqual(shared_files.data[0]["share_id"], share_id)
        self.assertEqual(shared_files.data[0]["owner_username"], "alice")

        shared_download = recipient_client.get(
            f"/api/shared-with-me/{share_id}/download/"
        )
        self.assertEqual(shared_download.status_code, 405)
        self.assertTrue(
            AuditLog.objects.filter(
                action="API Access Denied",
                user=recipient,
                outcome=AuditLog.Outcome.FAILURE,
                details__contains=f"GET /api/shared-with-me/{share_id}/download/",
            ).exists()
        )
        owner_download = recipient_client.post(
            f"/api/shared-with-me/{share_id}/download/",
            {'passcode': '123456'},
            format='json',
        )
        self.assertEqual(owner_download.status_code, 200)
        self.assertEqual(
            b"".join(owner_download.streaming_content),
            b"shared contents",
        )
        self.assertEqual(
            recipient_client.delete(f"/api/files/{file_id}/").status_code,
            404,
        )
        self.assertEqual(
            recipient_client.put(
                f"/api/files/{file_id}/passcode/",
                {'passcode': '999999'},
                format='json',
            ).status_code,
            404,
        )
        owner_events = self.client.get("/api/logs/").data
        download_event = next(
            event for event in owner_events
            if event["action"] == "File Downloaded" and event["username"] == "bob"
        )
        self.assertEqual(download_event["file_title"], "shared.txt")
        self.assertEqual(download_event["file_owner_username"], "alice")
        denied = next(
            event for event in self.client.get("/api/logs/").data
            if event["action"] == "File Access Denied"
        )
        self.assertEqual(denied["username"], "bob")
        self.assertEqual(denied["file_title"], "shared.txt")

    def test_owner_grants_and_revokes_original_replacement_through_share_permission(self):
        uploaded = self.client.post(
            "/api/files/",
            {
                "title": "source.txt",
                "file": SimpleUploadedFile("source.txt", b"original contents"),
            },
            format="multipart",
        )
        file_id = uploaded.data["id"]
        self.client.put(
            f"/api/files/{file_id}/passcode/",
            {"passcode": "123456"},
            format="json",
        )
        recipient = User.objects.create_user(username="bob", password="test-password")
        recipient_client = APIClient()
        recipient_client.force_authenticate(user=recipient)
        share_url = f"/api/files/{file_id}/share/"

        view_share = self.client.post(
            share_url,
            {"username": "bob", "permission": "view"},
            format="json",
        )
        self.assertEqual(view_share.status_code, 201)
        denied = recipient_client.post(
            f"/api/shared-with-me/{view_share.data['id']}/replace/",
            {
                "file": SimpleUploadedFile("view-copy.txt", b"should be denied"),
                "passcode": "123456",
            },
            format="multipart",
        )
        self.assertEqual(denied.status_code, 403)

        edit_share = self.client.post(
            share_url,
            {"username": "bob", "permission": "edit"},
            format="json",
        )
        self.assertEqual(edit_share.status_code, 200)
        self.assertEqual(edit_share.data["id"], view_share.data["id"])
        self.assertEqual(edit_share.data["permission"], "edit")
        self.assertTrue(edit_share.data["can_replace_original"])

        replacement_url = f"/api/shared-with-me/{edit_share.data['id']}/replace/"
        original_download = recipient_client.post(
            f"/api/shared-with-me/{edit_share.data['id']}/download/",
            {"passcode": "123456"},
            format="json",
        )
        self.assertEqual(b"".join(original_download.streaming_content), b"original contents")

        owner_granted_edit = recipient_client.post(
            replacement_url,
            {
                "file": SimpleUploadedFile("edited.txt", b"edited contents"),
                "passcode": "123456",
            },
            format="multipart",
        )
        self.assertEqual(owner_granted_edit.status_code, 200)

        staff_user = User.objects.create_user(
            username="staff",
            password="A-strong-example-Pass!738",
            is_staff=True,
        )
        staff_client = APIClient()
        self.assertTrue(
            staff_client.login(
                username=staff_user.username,
                password="A-strong-example-Pass!738",
            )
        )
        admin_change_url = f"/admin/api/fileshare/{edit_share.data['id']}/change/"
        admin_form = staff_client.get(admin_change_url)
        self.assertEqual(admin_form.status_code, 200)
        self.assertNotContains(admin_form, "can_replace_original")

        old_path = SecureFile.objects.get(pk=file_id).file.path
        edited = recipient_client.post(
            replacement_url,
            {
                "file": SimpleUploadedFile("edited.txt", b"edited contents"),
                "passcode": "123456",
            },
            format="multipart",
        )
        self.assertEqual(edited.status_code, 200)
        self.assertTrue(edited.data["replaced"])
        self.assertEqual(edited.data["file_id"], file_id)
        self.assertEqual(edited.data["title"], "edited.txt")
        self.assertEqual(edited.data["file_size"], len(b"edited contents"))

        secure_file = SecureFile.objects.get(pk=file_id)
        self.assertEqual(secure_file.title, "edited.txt")
        self.assertEqual(secure_file.encryption_version, 1)
        self.assertNotEqual(secure_file.file.path, old_path)
        self.assertFalse(Path(old_path).exists())
        with secure_file.file.open("rb") as stored:
            self.assertTrue(stored.read().startswith(MAGIC))

        recipient_download = recipient_client.post(
            f"/api/shared-with-me/{edit_share.data['id']}/download/",
            {"passcode": "123456"},
            format="json",
        )
        self.assertEqual(b"".join(recipient_download.streaming_content), b"edited contents")
        owner_download = self.client.get(f"/api/files/{file_id}/download/")
        self.assertEqual(b"".join(owner_download.streaming_content), b"edited contents")

        owner_file_data = self.client.get("/api/files/").data[0]
        self.assertEqual(owner_file_data["title"], "edited.txt")
        self.assertEqual(owner_file_data["shared_copies"], [])
        recipient_share_data = recipient_client.get("/api/shared-with-me/").data[0]
        self.assertEqual(recipient_share_data["permission"], "edit")
        self.assertTrue(recipient_share_data["can_replace_original"])
        self.assertTrue(
            AuditLog.objects.filter(
                action="Shared File Replaced",
                user=recipient,
                file_title="edited.txt",
            ).exists()
        )

        self.client.post(
            share_url,
            {"username": "bob", "permission": "view"},
            format="json",
        )
        after_revocation = recipient_client.post(
            replacement_url,
            {
                "file": SimpleUploadedFile("second.txt", b"not allowed"),
                "passcode": "123456",
            },
            format="multipart",
        )
        self.assertEqual(after_revocation.status_code, 403)
        secure_file.refresh_from_db()
        self.assertEqual(secure_file.title, "edited.txt")
        reenabled_edit = self.client.post(
            share_url,
            {"username": "bob", "permission": "edit"},
            format="json",
        )
        self.assertEqual(reenabled_edit.status_code, 200)
        self.assertTrue(reenabled_edit.data["can_replace_original"])

    def test_staff_can_view_audit_admin_and_users_cannot(self):
        audit_request = RequestFactory().get("/api/test/")
        audit_request.user = self.user
        record_audit(audit_request, "Test event")
        self.client.force_authenticate(user=None)
        self.assertNotEqual(self.client.get("/admin/api/auditlog/").status_code, 200)

        staff_user = User.objects.create_user(
            username="staff",
            password="A-strong-example-Pass!738",
            is_staff=True,
        )
        staff_client = APIClient()
        self.assertTrue(staff_client.login(username="staff", password="A-strong-example-Pass!738"))
        response = staff_client.get("/admin/api/auditlog/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test event")
        self.assertContains(staff_client.get("/admin/"), "Audit logs")
        self.assertEqual(staff_client.get("/admin/api/securefile/").status_code, 200)
        self.assertEqual(staff_client.get("/admin/api/fileshare/").status_code, 200)
        denied_delete = staff_client.get("/admin/api/securefile/1/delete/")
        self.assertEqual(denied_delete.status_code, 403)
        self.assertTrue(
            AuditLog.objects.filter(
                action="Admin Access Denied",
                user=staff_user,
                outcome=AuditLog.Outcome.FAILURE,
                details__contains="/admin/api/securefile/1/delete/",
            ).exists()
        )

        rejected_login = APIClient().post(
            "/admin/login/",
            {"username": "staff", "password": "incorrect-password"},
        )
        self.assertEqual(rejected_login.status_code, 200)
        self.assertTrue(
            AuditLog.objects.filter(
                action="Login Failed",
                actor_username="staff",
                outcome=AuditLog.Outcome.FAILURE,
            ).exists()
        )

    def test_admin_portal_is_staff_only_and_reports_platform_metrics(self):
        SecureFile.objects.create(
            user=self.user,
            title="admin-count.txt",
            file=SimpleUploadedFile("admin-count.txt", b"contents"),
            file_size=8,
        )
        self.assertEqual(self.client.get("/api/admin/overview/").status_code, 403)
        self.assertEqual(self.client.get("/api/admin/audit/").status_code, 403)

        staff_user = User.objects.create_user(username="portal-staff", is_staff=True)
        staff_client = APIClient()
        staff_client.force_authenticate(user=staff_user)
        response = staff_client.get("/api/admin/overview/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["counts"]["users"], 2)
        self.assertEqual(response.data["counts"]["documents"], 1)
        self.assertIn("portal-staff", {row["username"] for row in response.data["users"]})
        self.assertEqual(staff_client.get("/api/admin/audit/").status_code, 200)

    def test_staff_can_manage_every_document_and_revoke_any_share(self):
        owner = User.objects.create_user(username="document-owner")
        recipient = User.objects.create_user(username="document-recipient")
        secure_file = SecureFile.objects.create(
            user=owner,
            title="admin-secret.txt",
            category="Reports",
            file=SimpleUploadedFile("admin-secret.txt", b"original content"),
            file_size=len(b"original content"),
        )
        other_file = SecureFile.objects.create(
            user=recipient,
            title="another-private-file.txt",
            file=SimpleUploadedFile("another-private-file.txt", b"second document"),
            file_size=len(b"second document"),
        )
        share = FileShare.objects.create(file=secure_file, recipient=recipient)
        staff_user = User.objects.create_user(username="portal-staff", is_staff=True)
        staff_client = APIClient()
        staff_client.force_authenticate(user=staff_user)

        self.assertEqual(self.client.get("/api/admin/documents/").status_code, 403)
        self.assertEqual(
            self.client.get(
                f"/api/admin/documents/{secure_file.pk}/download/"
            ).status_code,
            403,
        )
        listing = staff_client.get(
            "/api/admin/documents/?search=admin-secret&page=1&page_size=1"
        )
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.data["count"], 1)
        self.assertEqual(listing.data["results"][0]["owner_username"], owner.username)
        self.assertEqual(listing.data["results"][0]["shares"][0]["username"], recipient.username)
        page_one = staff_client.get("/api/admin/documents/?page=1&page_size=1")
        page_two = staff_client.get("/api/admin/documents/?page=2&page_size=1")
        self.assertEqual(page_one.data["count"], 2)
        self.assertEqual(page_one.data["page_count"], 2)
        self.assertNotEqual(
            page_one.data["results"][0]["id"],
            page_two.data["results"][0]["id"],
        )

        metadata = staff_client.patch(
            f"/api/admin/documents/{secure_file.pk}/",
            {"title": "reviewed.txt", "category": "Reviewed"},
            format="json",
        )
        self.assertEqual(metadata.status_code, 200)
        secure_file.refresh_from_db()
        self.assertEqual(secure_file.title, "reviewed.txt")
        self.assertEqual(secure_file.category, "Reviewed")

        download = staff_client.get(
            f"/api/admin/documents/{secure_file.pk}/download/"
        )
        self.assertEqual(download.status_code, 200)
        self.assertEqual(b"".join(download.streaming_content), b"original content")
        self.assertTrue(
            AuditLog.objects.filter(
                action="File Downloaded by Admin",
                user=staff_user,
                file_title="reviewed.txt",
            ).exists()
        )

        replacement = staff_client.post(
            f"/api/admin/documents/{secure_file.pk}/replace/",
            {"file": SimpleUploadedFile("replacement.txt", b"replacement content")},
            format="multipart",
        )
        self.assertEqual(replacement.status_code, 200)
        secure_file.refresh_from_db()
        self.assertEqual(secure_file.encryption_version, 1)
        self.assertEqual(secure_file.title, "replacement.txt")
        replaced_download = staff_client.get(
            f"/api/admin/documents/{secure_file.pk}/download/"
        )
        self.assertEqual(replaced_download.status_code, 200)
        self.assertEqual(
            b"".join(replaced_download.streaming_content),
            b"replacement content",
        )

        revoke = staff_client.post(
            f"/api/admin/shares/{share.pk}/action/",
            {"action": "revoke"},
            format="json",
        )
        self.assertEqual(revoke.status_code, 200)
        share.refresh_from_db()
        self.assertIsNotNone(share.revoked_at)
        self.assertTrue(
            AuditLog.objects.filter(
                action="File Share Revoked by Admin",
                user=staff_user,
                file=secure_file,
            ).exists()
        )

        deleted = staff_client.delete(f"/api/admin/documents/{secure_file.pk}/")
        self.assertEqual(deleted.status_code, 204)
        self.assertFalse(SecureFile.objects.filter(pk=secure_file.pk).exists())
        self.assertTrue(SecureFile.objects.filter(pk=other_file.pk).exists())
        self.assertTrue(
            AuditLog.objects.filter(
                action="File Deleted by Admin",
                actor_username=staff_user.username,
                file_title="replacement.txt",
                file__isnull=True,
            ).exists()
        )

    def test_activity_summary_counts_exactly_the_last_24_hours(self):
        request = RequestFactory().get("/api/activity/summary/")
        request.user = self.user
        old_event = record_audit(request, "Old event")
        record_audit(request, "Recent event")
        AuditLog.objects.filter(pk=old_event.pk).update(
            timestamp=timezone.now() - timedelta(hours=25)
        )

        response = self.client.get("/api/activity/summary/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count_24h"], 1)
        self.assertEqual(len(response.data["events"]), 2)

    def test_admin_moderation_actions_enforce_timeouts_and_revoke_tokens(self):
        staff_user = User.objects.create_user(username="portal-staff", is_staff=True)
        target = User.objects.create_user(
            username="moderated-user",
            password="test-password",
        )
        staff_client = APIClient()
        staff_client.force_authenticate(user=staff_user)
        target_client = APIClient()
        login = target_client.post(
            "/api/token/",
            {"username": target.username, "password": "test-password"},
            format="json",
        )
        self.assertEqual(login.status_code, 200)
        target_client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {login.data['access']}"
        )
        self.assertEqual(target_client.get("/api/account/").status_code, 200)

        warning = staff_client.post(
            f"/api/admin/users/{target.pk}/action/",
            {"action": "warn", "note": "Policy violation"},
            format="json",
        )
        self.assertEqual(warning.status_code, 200)
        self.assertEqual(UserModeration.objects.get(user=target).warning_count, 1)

        timeout = staff_client.post(
            f"/api/admin/users/{target.pk}/action/",
            {"action": "timeout", "duration_minutes": 60},
            format="json",
        )
        self.assertEqual(timeout.status_code, 200)
        self.assertEqual(target_client.get("/api/account/").status_code, 401)

        clear_timeout = staff_client.post(
            f"/api/admin/users/{target.pk}/action/",
            {"action": "clear_timeout"},
            format="json",
        )
        self.assertEqual(clear_timeout.status_code, 200)
        self.assertEqual(target_client.get("/api/account/").status_code, 401)

        re_login = APIClient().post(
            "/api/token/",
            {"username": target.username, "password": "test-password"},
            format="json",
        )
        self.assertEqual(re_login.status_code, 200)
        target_client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {re_login.data['access']}"
        )
        self.assertEqual(target_client.get("/api/account/").status_code, 200)

        block = staff_client.post(
            f"/api/admin/users/{target.pk}/action/",
            {"action": "block", "note": "Repeated abuse"},
            format="json",
        )
        self.assertEqual(block.status_code, 200)
        self.assertEqual(target_client.get("/api/account/").status_code, 401)

        unblock = staff_client.post(
            f"/api/admin/users/{target.pk}/action/",
            {"action": "unblock"},
            format="json",
        )
        self.assertEqual(unblock.status_code, 200)
        self.assertEqual(target_client.get("/api/account/").status_code, 401)
        self.assertEqual(AuthTokenVersion.objects.get(user=target).version, 4)
        self.assertTrue(
            AuditLog.objects.filter(
                action="Admin User Blocked",
                file__isnull=True,
                outcome=AuditLog.Outcome.SUCCESS,
            ).exists()
        )

    def test_admin_cannot_moderate_self_or_another_admin(self):
        staff_user = User.objects.create_user(username="portal-staff", is_staff=True)
        staff_client = APIClient()
        staff_client.force_authenticate(user=staff_user)
        self.assertEqual(
            staff_client.post(
                f"/api/admin/users/{staff_user.pk}/action/",
                {"action": "block"},
                format="json",
            ).status_code,
            400,
        )

        other_admin = User.objects.create_user(username="other-admin", is_superuser=True)
        self.assertEqual(
            staff_client.post(
                f"/api/admin/users/{other_admin.pk}/action/",
                {"action": "block"},
                format="json",
            ).status_code,
            400,
        )
        other_admin.refresh_from_db()
        self.assertTrue(other_admin.is_active)

    def test_bootstrap_admin_requires_configured_credentials_and_is_one_time(self):
        with patch.dict("os.environ", {}, clear=False):
            for name in (
                "SV_ADMIN_USERNAME",
                "SV_ADMIN_EMAIL",
                "SV_ADMIN_PASSWORD",
            ):
                os.environ.pop(name, None)
            with self.assertRaises(CommandError):
                call_command("bootstrap_admin")

        credentials = {
            "SV_ADMIN_USERNAME": "sv-operator",
            "SV_ADMIN_EMAIL": "operator@example.test",
            "SV_ADMIN_PASSWORD": "A-very-long-password-that-is-not-common-77!",
        }
        with patch.dict("os.environ", credentials, clear=False):
            call_command("bootstrap_admin", verbosity=0)
            admin_user = User.objects.get(username="sv-operator")
            self.assertTrue(admin_user.is_staff)
            self.assertTrue(admin_user.is_superuser)
            self.assertNotEqual(admin_user.password, credentials["SV_ADMIN_PASSWORD"])
            with self.assertRaises(CommandError):
                call_command("bootstrap_admin", verbosity=0)

    def test_superuser_can_delete_file_and_copies_without_deleting_audit(self):
        secure_file = SecureFile.objects.create(
            user=self.user,
            title="admin-delete.txt",
            file=SimpleUploadedFile("admin-delete.txt", b"source contents"),
            file_size=len(b"source contents"),
        )
        recipient = User.objects.create_user(username="bob", password="test-password")
        share = FileShare.objects.create(
            file=secure_file,
            recipient=recipient,
            permission=FileShare.Permission.EDIT,
        )
        revision = SharedFileRevision.objects.create(
            source_file=secure_file,
            share=share,
            editor=recipient,
            title="admin-copy.txt",
            file=SimpleUploadedFile("admin-copy.txt", b"copy contents"),
            file_size=len(b"copy contents"),
        )
        source_path = secure_file.file.path
        revision_path = revision.file.path

        admin_user = User.objects.create_superuser(
            username="root",
            email="root@example.test",
            password="A-strong-example-Pass!738",
        )
        admin_client = APIClient()
        self.assertTrue(
            admin_client.login(
                username=admin_user.username,
                password="A-strong-example-Pass!738",
            )
        )
        confirmation = admin_client.get(f"/admin/api/securefile/{secure_file.pk}/delete/")
        self.assertEqual(confirmation.status_code, 200)
        deleted = admin_client.post(
            f"/admin/api/securefile/{secure_file.pk}/delete/",
            {"post": "yes"},
        )
        self.assertEqual(deleted.status_code, 302)
        self.assertFalse(SecureFile.objects.filter(pk=secure_file.pk).exists())
        self.assertFalse(FileShare.objects.filter(pk=share.pk).exists())
        self.assertFalse(SharedFileRevision.objects.filter(pk=revision.pk).exists())
        self.assertFalse(Path(source_path).exists())
        self.assertFalse(Path(revision_path).exists())
        event = AuditLog.objects.get(action="File Deleted by Admin")
        self.assertEqual(event.actor_username, "root")
        self.assertEqual(event.file_title, "admin-delete.txt")
        self.assertEqual(event.file_owner_username, self.user.username)
        self.assertIsNone(event.file_id)

    def test_share_requires_owner_passcode(self):
        uploaded = self.client.post(
            "/api/files/",
            {
                "title": "not-ready.txt",
                "file": SimpleUploadedFile("not-ready.txt", b"private"),
            },
            format="multipart",
        )
        recipient = User.objects.create_user(username="bob", password="test-password")

        response = self.client.post(
            f"/api/files/{uploaded.data['id']}/share/",
            {"username": recipient.username},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn('passcode', response.data)
        self.assertFalse(FileShare.objects.exists())

    def test_owner_can_set_change_and_remove_passcode(self):
        uploaded = self.client.post(
            "/api/files/",
            {
                "title": "passcode.txt",
                "file": SimpleUploadedFile("passcode.txt", b"private"),
            },
            format="multipart",
        )
        file_id = uploaded.data["id"]
        recipient = User.objects.create_user(username="bob", password="test-password")

        invalid = self.client.put(
            f"/api/files/{file_id}/passcode/",
            {'passcode': '12345a'},
            format='json',
        )
        self.assertEqual(invalid.status_code, 400)

        set_response = self.client.put(
            f"/api/files/{file_id}/passcode/",
            {'passcode': '123456'},
            format='json',
        )
        self.assertEqual(set_response.status_code, 200)
        secure_file = SecureFile.objects.get(pk=file_id)
        self.assertTrue(secure_file.passcode_hash)
        self.assertNotEqual(secure_file.passcode_hash, '123456')
        self.assertNotIn('passcode', set_response.data)

        share = self.client.post(
            f"/api/files/{file_id}/share/",
            {'username': recipient.username},
            format='json',
        )
        self.assertEqual(share.status_code, 201)

        changed = self.client.put(
            f"/api/files/{file_id}/passcode/",
            {'passcode': '654321'},
            format='json',
        )
        self.assertEqual(changed.status_code, 200)
        secure_file.refresh_from_db()
        self.assertTrue(check_password('654321', secure_file.passcode_hash))
        self.assertFalse(check_password('123456', secure_file.passcode_hash))
        shared_record = FileShare.objects.get(pk=share.data['id'])
        shared_record.file.refresh_from_db()
        self.assertEqual(shared_record.file_id, file_id)
        self.assertFalse(check_password('123456', shared_record.file.passcode_hash))
        recipient_client = APIClient()
        recipient_client.force_authenticate(user=recipient)
        old_passcode = recipient_client.post(
            f"/api/shared-with-me/{share.data['id']}/download/",
            {'passcode': '123456'},
            format='json',
        )
        self.assertEqual(old_passcode.status_code, 403)
        failed_event = next(
            event for event in self.client.get("/api/logs/").data
            if event["action"] == "File Passcode Failed"
        )
        self.assertEqual(failed_event["action"], "File Passcode Failed")
        self.assertEqual(failed_event["username"], "bob")
        self.assertEqual(failed_event["outcome"], "failure")
        new_passcode = recipient_client.post(
            f"/api/shared-with-me/{share.data['id']}/download/",
            {'passcode': '654321'},
            format='json',
        )
        self.assertEqual(new_passcode.status_code, 200)
        new_passcode.close()

        removed = self.client.delete(f"/api/files/{file_id}/passcode/")
        self.assertEqual(removed.status_code, 200)
        secure_file.refresh_from_db()
        self.assertFalse(secure_file.passcode_hash)
        share_record = FileShare.objects.get(pk=share.data['id'])
        self.assertIsNotNone(share_record.revoked_at)
        self.assertEqual(
            recipient_client.post(
                f"/api/shared-with-me/{share_record.pk}/download/",
                {'passcode': '654321'},
                format='json',
            ).status_code,
            404,
        )

    def test_incorrect_passcode_locks_share_after_five_attempts(self):
        uploaded = self.client.post(
            "/api/files/",
            {
                "title": "locked.txt",
                "file": SimpleUploadedFile("locked.txt", b"private"),
            },
            format="multipart",
        )
        file_id = uploaded.data["id"]
        self.client.put(
            f"/api/files/{file_id}/passcode/",
            {'passcode': '123456'},
            format='json',
        )
        secure_file = SecureFile.objects.get(pk=file_id)
        self.assertTrue(check_password('123456', secure_file.passcode_hash))
        self.assertFalse(check_password('000000', secure_file.passcode_hash))
        recipient = User.objects.create_user(username="bob", password="test-password")
        share = self.client.post(
            f"/api/files/{file_id}/share/",
            {'username': recipient.username},
            format='json',
        )
        recipient_client = APIClient()
        recipient_client.force_authenticate(user=recipient)

        for attempt in range(4):
            response = recipient_client.post(
                f"/api/shared-with-me/{share.data['id']}/download/",
                {'passcode': '000000'},
                format='json',
            )
            self.assertEqual(response.status_code, 403, attempt)

        locked = recipient_client.post(
            f"/api/shared-with-me/{share.data['id']}/download/",
            {'passcode': '000000'},
            format='json',
        )
        self.assertEqual(locked.status_code, 429)
        self.assertIsNotNone(
            FileShare.objects.get(pk=share.data['id']).passcode_locked_until
        )
        still_locked = recipient_client.post(
            f"/api/shared-with-me/{share.data['id']}/download/",
            {'passcode': '123456'},
            format='json',
        )
        self.assertEqual(still_locked.status_code, 429)
        self.assertTrue(
            AuditLog.objects.filter(
                user=recipient,
                file_title="locked.txt",
                action="File Passcode Failed",
                outcome=AuditLog.Outcome.FAILURE,
            ).exists()
        )
        self.assertTrue(
            AuditLog.objects.filter(
                user=recipient,
                file_title="locked.txt",
                action="File Passcode Lockout",
                outcome=AuditLog.Outcome.FAILURE,
            ).exists()
        )

    def test_owner_can_revoke_share_and_recipient_loses_access(self):
        uploaded = self.client.post(
            "/api/files/",
            {
                "title": "revoke.txt",
                "file": SimpleUploadedFile("revoke.txt", b"revoke me"),
            },
            format="multipart",
        )
        file_id = uploaded.data["id"]
        self.client.put(
            f"/api/files/{file_id}/passcode/",
            {'passcode': '123456'},
            format='json',
        )
        recipient = User.objects.create_user(username="bob", password="test-password")
        recipient_client = APIClient()
        recipient_client.force_authenticate(user=recipient)

        share = self.client.post(
            f"/api/files/{file_id}/share/",
            {"username": "bob"},
            format="json",
        )
        self.assertEqual(share.status_code, 201)
        shared_record = FileShare.objects.get(pk=share.data['id'])
        shared_record.file.refresh_from_db()
        self.assertFalse(check_password('000000', shared_record.file.passcode_hash))

        other_user = User.objects.create_user(username="charlie", password="test-password")
        other_client = APIClient()
        other_client.force_authenticate(user=other_user)
        unauthorized_revoke = other_client.delete(f"/api/shares/{share.data['id']}/")
        self.assertEqual(unauthorized_revoke.status_code, 404)
        self.assertIsNone(FileShare.objects.get(pk=share.data["id"]).revoked_at)

        revoke = self.client.delete(f"/api/shares/{share.data['id']}/")
        self.assertEqual(revoke.status_code, 204)
        self.assertTrue(
            AuditLog.objects.filter(
                action="File Share Revoked",
                user=self.user,
                file_title="revoke.txt",
            ).exists()
        )
        self.assertEqual(recipient_client.get("/api/shared-with-me/").data, [])
        self.assertEqual(
            recipient_client.get(f"/api/shared-with-me/{share.data['id']}/").status_code,
            404,
        )
        self.assertEqual(
            recipient_client.post(
                f"/api/shared-with-me/{share.data['id']}/download/",
                {'passcode': '123456'},
                format='json',
            ).status_code,
            404,
        )
        self.assertTrue(
            AuditLog.objects.filter(
                action="API Access Denied",
                user=recipient,
                file_title="revoke.txt",
                outcome=AuditLog.Outcome.FAILURE,
            ).exists()
        )

    def test_expired_share_cannot_be_accessed_through_any_route(self):
        uploaded = self.client.post(
            "/api/files/",
            {
                "title": "expired.txt",
                "file": SimpleUploadedFile("expired.txt", b"expired"),
            },
            format="multipart",
        )
        secure_file = SecureFile.objects.get(pk=uploaded.data["id"])
        recipient = User.objects.create_user(username="bob", password="test-password")
        share = FileShare.objects.create(
            file=secure_file,
            recipient=recipient,
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        recipient_client = APIClient()
        recipient_client.force_authenticate(user=recipient)

        self.assertEqual(recipient_client.get("/api/shared-with-me/").data, [])
        self.assertEqual(
            recipient_client.get(f"/api/shared-with-me/{share.pk}/").status_code,
            404,
        )
        self.assertEqual(
            recipient_client.get(
                f"/api/shared-with-me/{share.pk}/revisions/"
            ).status_code,
            404,
        )
        self.assertEqual(
            recipient_client.post(
                f"/api/shared-with-me/{share.pk}/replace/",
                {
                    "file": SimpleUploadedFile("replacement.txt", b"no access"),
                    "passcode": "123456",
                },
                format="multipart",
            ).status_code,
            404,
        )
        self.assertEqual(
            recipient_client.post(
                f"/api/shared-with-me/{share.pk}/download/",
                {'passcode': '123456'},
                format='json',
            ).status_code,
            404,
        )
        self.assertTrue(
            AuditLog.objects.filter(
                action="API Access Denied",
                user=recipient,
                file=secure_file,
                outcome=AuditLog.Outcome.FAILURE,
            ).exists()
        )

    def test_share_end_date_revokes_recipient_but_keeps_owner_access(self):
        uploaded = self.client.post(
            "/api/files/",
            {
                "title": "owner-keeps-this.txt",
                "file": SimpleUploadedFile("owner-keeps-this.txt", b"owner data"),
            },
            format="multipart",
        )
        self.assertEqual(uploaded.status_code, 201)
        file_id = uploaded.data["id"]
        secure_file = SecureFile.objects.get(pk=file_id)
        recipient = User.objects.create_user(username="deadline-recipient")
        recipient_client = APIClient()
        recipient_client.force_authenticate(user=recipient)

        passcode_response = self.client.put(
            f"/api/files/{file_id}/passcode/",
            {"passcode": "123456"},
            format="json",
        )
        self.assertEqual(passcode_response.status_code, 200)
        share = FileShare.objects.create(
            file=secure_file,
            recipient=recipient,
            permission=FileShare.Permission.EDIT,
            can_replace_original=True,
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        revision = SharedFileRevision.objects.create(
            source_file=secure_file,
            share=share,
            editor=recipient,
            title="revision.txt",
            file=SimpleUploadedFile("revision.txt", b"revision"),
            file_size=8,
        )

        self.assertEqual(recipient_client.get("/api/shared-with-me/").data, [])
        self.assertEqual(
            recipient_client.get(f"/api/shared-with-me/{share.pk}/").status_code,
            404,
        )
        self.assertEqual(
            recipient_client.post(
                f"/api/shared-with-me/{share.pk}/download/",
                {"passcode": "123456"},
                format="json",
            ).status_code,
            404,
        )
        self.assertEqual(
            recipient_client.post(
                f"/api/shared-with-me/{share.pk}/replace/",
                {
                    "file": SimpleUploadedFile("replacement.txt", b"replacement"),
                    "passcode": "123456",
                },
                format="multipart",
            ).status_code,
            404,
        )
        self.assertEqual(
            recipient_client.get(f"/api/revisions/{revision.pk}/download/").status_code,
            404,
        )
        self.assertTrue(
            AuditLog.objects.filter(
                action="API Access Denied",
                user=recipient,
                file=secure_file,
                outcome=AuditLog.Outcome.FAILURE,
            ).exists()
        )
        self.assertEqual(
            self.client.get(f"/api/files/{file_id}/download/").status_code,
            200,
        )
        owner_share = self.client.get(f"/api/files/{file_id}/share/").data[0]
        self.assertFalse(owner_share["active"])

    def test_owner_cannot_share_with_unknown_or_self_user(self):
        uploaded = self.client.post(
            "/api/files/",
            {
                "title": "private.txt",
                "file": SimpleUploadedFile("private.txt", b"private"),
            },
            format="multipart",
        )
        url = f"/api/files/{uploaded.data['id']}/share/"

        unknown = self.client.post(url, {"username": "unknown"}, format="json")
        self.assertEqual(unknown.status_code, 400)

        self_share = self.client.post(url, {"username": "alice"}, format="json")
        self.assertEqual(self_share.status_code, 400)
        self.assertFalse(FileShare.objects.exists())

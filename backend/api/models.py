# backend/api/models.py
from django.db import models
from django.contrib.auth.models import User

class SecureFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='secure_files')
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=100, default='Uncategorized')
    file = models.FileField(upload_to='encrypted_vault/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    file_size = models.PositiveBigIntegerField(default=0)
    encryption_algorithm = models.CharField(max_length=50, default='AES-256-GCM')
    encryption_version = models.PositiveSmallIntegerField(default=0)
    passcode_hash = models.CharField(max_length=128, blank=True, default='')

    def __str__(self):
        return f"{self.title} ({self.user.username})"


class AuthTokenVersion(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='token_version')
    version = models.PositiveBigIntegerField(default=0)


class UserModeration(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='moderation',
    )
    warning_count = models.PositiveIntegerField(default=0)
    suspended_until = models.DateTimeField(null=True, blank=True)
    last_note = models.CharField(max_length=500, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='moderation_actions',
    )


class FileShare(models.Model):
    class Permission(models.TextChoices):
        VIEW = 'view', 'View'
        EDIT = 'edit', 'Edit'

    file = models.ForeignKey(SecureFile, on_delete=models.CASCADE, related_name='shares')
    recipient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='received_file_shares',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    permission = models.CharField(
        max_length=8,
        choices=Permission.choices,
        default=Permission.VIEW,
    )
    can_replace_original = models.BooleanField(default=False)
    failed_passcode_attempts = models.PositiveSmallIntegerField(default=0)
    passcode_locked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['file', 'recipient'],
                name='unique_file_share_recipient',
            ),
        ]

    def __str__(self):
        return f"{self.file.title} shared with {self.recipient.username}"


class SharedFileRevision(models.Model):
    source_file = models.ForeignKey(
        SecureFile,
        on_delete=models.CASCADE,
        related_name='shared_revisions',
    )
    share = models.ForeignKey(
        FileShare,
        on_delete=models.CASCADE,
        related_name='revisions',
    )
    editor = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='shared_file_revisions',
    )
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='encrypted_revisions/')
    file_size = models.PositiveBigIntegerField(default=0)
    encryption_algorithm = models.CharField(max_length=50, default='AES-256-GCM')
    encryption_version = models.PositiveSmallIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} revised by {self.editor.username}"


class AuditLog(models.Model):
    class Outcome(models.TextChoices):
        SUCCESS = 'success', 'Success'
        FAILURE = 'failure', 'Failure'

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    actor_username = models.CharField(max_length=150, blank=True)
    file = models.ForeignKey(
        SecureFile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_events',
    )
    file_title = models.CharField(max_length=255, blank=True)
    file_owner = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='owned_file_audit_events',
    )
    file_owner_username = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=255)
    outcome = models.CharField(
        max_length=16,
        choices=Outcome.choices,
        default=Outcome.SUCCESS,
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True)
    previous_hash = models.CharField(max_length=64, blank=True, default='')
    integrity_hash = models.CharField(max_length=64, blank=True, default='')

    class Meta:
        indexes = [
            models.Index(
                fields=['-timestamp'],
                name='api_auditlo_timesta_96ac8f_idx',
            ),
            models.Index(
                fields=['outcome', '-timestamp'],
                name='api_auditlo_outcome_96a70e_idx',
            ),
        ]

    def __str__(self):
        actor = self.actor_username or "Anonymous"
        target = self.file_title or "No file"
        return f"[{self.timestamp}] {self.action} - {actor} - {target}"


class AuditChainState(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    last_hash = models.CharField(max_length=64, default='0' * 64)

    def __str__(self):
        return f"Audit chain head: {self.last_hash[:12]}"

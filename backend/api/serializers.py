# backend/api/serializers.py
import re

from django.utils import timezone
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.conf import settings

from .models import FileShare, SecureFile, AuditLog, SharedFileRevision


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {
            'email': {'required': False, 'allow_blank': True},
        }

    def validate_password(self, value):
        username = self.initial_data.get('username', '')
        user = User(username=username) if isinstance(username, str) else None
        try:
            validate_password(value, user=user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages) from exc
        return value

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class SecureFileSerializer(serializers.ModelSerializer):
    file = serializers.FileField(write_only=True)
    has_passcode = serializers.SerializerMethodField()
    shared_copies = serializers.SerializerMethodField()
    owner_username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = SecureFile
        fields = [
            'id',
            'title',
            'category',
            'owner_username',
            'file',
            'uploaded_at',
            'file_size',
            'encryption_algorithm',
            'has_passcode',
            'shared_copies',
        ]
        read_only_fields = [
            'uploaded_at',
            'file_size',
            'encryption_algorithm',
            'has_passcode',
        ]

    def get_has_passcode(self, obj):
        return bool(obj.passcode_hash)

    def get_shared_copies(self, obj):
        copies = obj.shared_revisions.select_related('editor').order_by('-created_at')
        return SharedFileRevisionSerializer(copies, many=True).data

    def validate_file(self, value):
        if not value.name:
            raise serializers.ValidationError("A file name is required.")
        if len(value.name) > 255:
            raise serializers.ValidationError(
                "The uploaded file name must be no longer than 255 characters."
            )
        if value.size == 0:
            raise serializers.ValidationError("Empty files cannot be uploaded.")
        if value.size > settings.MAX_FILE_UPLOAD_SIZE:
            max_size_mb = settings.MAX_FILE_UPLOAD_SIZE // (1024 * 1024)
            raise serializers.ValidationError(
                f"File must be no larger than {max_size_mb} MB."
            )
        return value

    def validate_title(self, value):
        title = value.strip()
        if not title:
            raise serializers.ValidationError("A document name is required.")
        return title

    def validate_category(self, value):
        category = value.strip()
        if not category:
            raise serializers.ValidationError("A category is required.")
        return category

class FileShareCreateSerializer(serializers.Serializer):
    username = serializers.SlugRelatedField(
        slug_field='username',
        source='recipient',
        queryset=User.objects.all(),
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    permission = serializers.ChoiceField(
        choices=FileShare.Permission.choices,
        default=FileShare.Permission.VIEW,
    )

    def validate(self, attrs):
        request = self.context['request']
        secure_file = self.context.get('file')
        if secure_file is not None and not secure_file.passcode_hash:
            raise serializers.ValidationError(
                {'passcode': 'Set a file passcode before sharing this file.'}
            )
        if attrs['recipient'] == request.user:
            raise serializers.ValidationError(
                {'username': 'You cannot share a file with yourself.'}
            )
        expires_at = attrs.get('expires_at')
        if expires_at and expires_at <= timezone.now():
            raise serializers.ValidationError(
                {'expires_at': 'The expiry time must be in the future.'}
            )
        return attrs


class FilePasscodeSerializer(serializers.Serializer):
    passcode = serializers.CharField(
        min_length=6,
        max_length=6,
        trim_whitespace=False,
        write_only=True,
    )

    def validate_passcode(self, value):
        if not re.fullmatch(r'[0-9]{6}', value):
            raise serializers.ValidationError('Passcode must be exactly 6 digits.')
        return value


class PasscodeEntrySerializer(serializers.Serializer):
    passcode = serializers.CharField(
        min_length=6,
        max_length=6,
        trim_whitespace=False,
        write_only=True,
    )

    def validate_passcode(self, value):
        if not re.fullmatch(r'[0-9]{6}', value):
            raise serializers.ValidationError('Passcode must be exactly 6 digits.')
        return value


class FileShareSerializer(serializers.ModelSerializer):
    file_id = serializers.IntegerField(source='file.id', read_only=True)
    username = serializers.CharField(source='recipient.username', read_only=True)
    active = serializers.SerializerMethodField()

    class Meta:
        model = FileShare
        fields = [
            'id',
            'file_id',
            'username',
            'permission',
            'can_replace_original',
            'created_at',
            'expires_at',
            'revoked_at',
            'active',
        ]
        read_only_fields = fields

    def get_active(self, obj):
        return (
            obj.revoked_at is None
            and (obj.expires_at is None or obj.expires_at > timezone.now())
        )


class SharedFileSerializer(serializers.ModelSerializer):
    share_id = serializers.IntegerField(source='id', read_only=True)
    file_id = serializers.IntegerField(source='file.id', read_only=True)
    title = serializers.CharField(source='file.title', read_only=True)
    owner_username = serializers.CharField(source='file.user.username', read_only=True)
    category = serializers.CharField(source='file.category', read_only=True)
    uploaded_at = serializers.DateTimeField(source='file.uploaded_at', read_only=True)
    file_size = serializers.IntegerField(source='file.file_size', read_only=True)
    encryption_algorithm = serializers.CharField(
        source='file.encryption_algorithm',
        read_only=True,
    )
    revisions = serializers.SerializerMethodField()

    class Meta:
        model = FileShare
        fields = [
            'share_id',
            'file_id',
            'title',
            'owner_username',
            'category',
            'uploaded_at',
            'file_size',
            'encryption_algorithm',
            'permission',
            'can_replace_original',
            'revisions',
            'created_at',
            'expires_at',
        ]

    def get_revisions(self, obj):
        revisions = obj.revisions.filter(editor=obj.recipient).order_by('-created_at')
        return SharedFileRevisionSerializer(revisions, many=True).data


class SharedFileRevisionSerializer(serializers.ModelSerializer):
    editor_username = serializers.CharField(source='editor.username', read_only=True)
    source_file_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = SharedFileRevision
        fields = [
            'id',
            'source_file_id',
            'title',
            'file_size',
            'editor_username',
            'created_at',
        ]
        read_only_fields = fields


class SharedFileRevisionCreateSerializer(serializers.Serializer):
    file = serializers.FileField()
    passcode = serializers.CharField(
        min_length=6,
        max_length=6,
        trim_whitespace=False,
        write_only=True,
    )

    def validate_file(self, value):
        if not value.name:
            raise serializers.ValidationError("A file name is required.")
        if len(value.name) > 255:
            raise serializers.ValidationError(
                "The uploaded file name must be no longer than 255 characters."
            )
        if value.size == 0:
            raise serializers.ValidationError("Empty files cannot be uploaded.")
        if value.size > settings.MAX_FILE_UPLOAD_SIZE:
            max_size_mb = settings.MAX_FILE_UPLOAD_SIZE // (1024 * 1024)
            raise serializers.ValidationError(
                f"File must be no larger than {max_size_mb} MB."
            )
        return value

    def validate_passcode(self, value):
        if not re.fullmatch(r'[0-9]{6}', value):
            raise serializers.ValidationError('Passcode must be exactly 6 digits.')
        return value


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='actor_username', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id',
            'username',
            'action',
            'outcome',
            'file_title',
            'file_owner_username',
            'ip_address',
            'timestamp',
            'details',
            'previous_hash',
            'integrity_hash',
        ]
        read_only_fields = fields


class AdminModerationActionSerializer(serializers.Serializer):
    action = serializers.ChoiceField(
        choices=['warn', 'timeout', 'clear_timeout', 'block', 'unblock']
    )
    duration_minutes = serializers.IntegerField(
        required=False,
        min_value=1,
        max_value=43200,
    )
    note = serializers.CharField(required=False, allow_blank=True, max_length=500)

    def validate(self, attrs):
        if attrs['action'] == 'timeout' and 'duration_minutes' not in attrs:
            raise serializers.ValidationError(
                {'duration_minutes': 'Choose a timeout duration in minutes.'}
            )
        if attrs['action'] == 'warn' and not attrs.get('note', '').strip():
            raise serializers.ValidationError(
                {'note': 'Provide a reason for the warning.'}
            )
        return attrs


class AdminUserProfileSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    last_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    email = serializers.EmailField(required=False, allow_blank=True, max_length=254)

    def validate(self, attrs):
        unknown_fields = set(self.initial_data) - set(self.fields)
        if unknown_fields:
            raise serializers.ValidationError({
                field: 'This profile field cannot be changed here.'
                for field in sorted(unknown_fields)
            })
        if not attrs:
            raise serializers.ValidationError(
                'Provide at least one profile field to update.'
            )
        return attrs


class AdminSecureFileSerializer(serializers.ModelSerializer):
    owner_username = serializers.CharField(source='user.username', read_only=True)
    has_passcode = serializers.SerializerMethodField()
    revision_count = serializers.IntegerField(
        source='shared_revisions.count',
        read_only=True,
    )
    shares = serializers.SerializerMethodField()

    class Meta:
        model = SecureFile
        fields = [
            'id',
            'title',
            'category',
            'owner_username',
            'uploaded_at',
            'file_size',
            'encryption_algorithm',
            'has_passcode',
            'revision_count',
            'shares',
        ]
        read_only_fields = fields

    def get_has_passcode(self, obj):
        return bool(obj.passcode_hash)

    def get_shares(self, obj):
        now = timezone.now()
        return [
            {
                'id': share.pk,
                'username': share.recipient.get_username(),
                'permission': share.permission,
                'can_replace_original': share.can_replace_original,
                'created_at': share.created_at,
                'expires_at': share.expires_at,
                'revoked_at': share.revoked_at,
                'active': (
                    share.revoked_at is None
                    and (share.expires_at is None or share.expires_at > now)
                ),
            }
            for share in obj.shares.all()
        ]


class AdminSecureFileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecureFile
        fields = ['title', 'category']

    def validate_title(self, value):
        title = value.strip()
        if not title:
            raise serializers.ValidationError('A document name is required.')
        return title

    def validate_category(self, value):
        category = value.strip()
        if not category:
            raise serializers.ValidationError('A category is required.')
        return category


class AdminSecureFileReplacementSerializer(serializers.Serializer):
    file = serializers.FileField()

    def validate_file(self, value):
        if not value.name:
            raise serializers.ValidationError('A file name is required.')
        if len(value.name) > 255:
            raise serializers.ValidationError(
                'The uploaded file name must be no longer than 255 characters.'
            )
        if value.size == 0:
            raise serializers.ValidationError('Empty files cannot be uploaded.')
        if value.size > settings.MAX_FILE_UPLOAD_SIZE:
            max_size_mb = settings.MAX_FILE_UPLOAD_SIZE // (1024 * 1024)
            raise serializers.ValidationError(
                f'File must be no larger than {max_size_mb} MB.'
            )
        return value

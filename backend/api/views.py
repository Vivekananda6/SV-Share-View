import hmac
import logging
import uuid
from datetime import timedelta

from cryptography.exceptions import InvalidTag
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core.files import File
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.http import FileResponse
from django.db.models import Count, Q
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.http import Http404
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.exceptions import (
    APIException,
    AuthenticationFailed,
    NotFound,
    PermissionDenied,
    Throttled,
    ValidationError,
)
from rest_framework.views import exception_handler
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)
from rest_framework_simplejwt.settings import api_settings as jwt_api_settings
from rest_framework_simplejwt.tokens import get_md5_hash_password
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.contrib.auth import get_user_model
from django.db.models import F

from .audit_integrity import append_audit_checkpoint, sign_audit_event
from .crypto import InvalidEncryptedFile, decrypt_file, encrypt_file
from .models import (
    AuditChainState,
    AuditLog,
    AuthTokenVersion,
    FileShare,
    SecureFile,
    SharedFileRevision,
    UserModeration,
)
from .serializers import (
    AuditLogSerializer,
    AdminModerationActionSerializer,
    FileShareCreateSerializer,
    FileShareSerializer,
    FilePasscodeSerializer,
    PasscodeEntrySerializer,
    AdminSecureFileSerializer,
    AdminSecureFileUpdateSerializer,
    AdminSecureFileReplacementSerializer,
    RegisterSerializer,
    SecureFileSerializer,
    SharedFileSerializer,
    SharedFileRevisionCreateSerializer,
    SharedFileRevisionSerializer,
)

logger = logging.getLogger(__name__)
MAX_PASSCODE_ATTEMPTS = 5
PASSCODE_LOCKOUT = timedelta(minutes=15)


def record_audit(
    request,
    action,
    *,
    file=None,
    actor_user=None,
    actor_username=None,
    outcome=AuditLog.Outcome.SUCCESS,
    details='',
):
    actor = actor_user
    if actor is None and request.user.is_authenticated:
        actor = request.user
    owner = file.user if file else None
    with transaction.atomic():
        chain_state = AuditChainState.objects.select_for_update().get(pk=1)
        event = AuditLog.objects.create(
            user=actor,
            actor_username=(
                actor.get_username() if actor else actor_username or ''
            ),
            file=file,
            file_title=file.title if file else '',
            file_owner=owner,
            file_owner_username=owner.get_username() if owner else '',
            action=action,
            outcome=outcome,
            details=details,
            ip_address=request.META.get('REMOTE_ADDR'),
            previous_hash=chain_state.last_hash,
        )
        event.integrity_hash = sign_audit_event(event, chain_state.last_hash)
        event.save(update_fields=['integrity_hash'])
        chain_state.last_hash = event.integrity_hash
        chain_state.save(update_fields=['last_hash'])
        append_audit_checkpoint(event)
    return event


def _file_for_denied_request(request):
    parts = request.path_info.strip('/').split('/')
    try:
        if len(parts) >= 3 and parts[1] == 'files':
            return SecureFile.objects.select_related('user').filter(pk=parts[2]).first()
        if len(parts) >= 3 and parts[1] == 'shared-with-me':
            share = FileShare.objects.select_related('file__user').filter(
                pk=parts[2]
            ).first()
            return share.file if share else None
        if len(parts) >= 3 and parts[1] == 'revisions':
            revision = SharedFileRevision.objects.select_related(
                'source_file__user'
            ).filter(pk=parts[2]).first()
            return revision.source_file if revision else None
        if len(parts) >= 3 and parts[1] == 'shares':
            share = FileShare.objects.select_related('file__user').filter(
                pk=parts[2]
            ).first()
            return share.file if share else None
    except (TypeError, ValueError):
        return None
    return None


def audit_api_exception(exc, context):
    response = exception_handler(exc, context)
    if response is None or response.status_code not in (401, 403, 404, 405, 429):
        return response

    request = context.get('request')
    if request is not None:
        actor = request.user if request.user.is_authenticated else None
        record_audit(
            request,
            'API Access Denied',
            file=_file_for_denied_request(request),
            actor_user=actor,
            outcome=AuditLog.Outcome.FAILURE,
            details=(
                f'{request.method} {request.path_info} returned '
                f'HTTP {response.status_code}.'
            ),
        )
    return response


class AuditedTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token_version, _ = AuthTokenVersion.objects.get_or_create(user=user)
        token['token_version'] = token_version.version
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        record_audit(self.context['request'], "Login Succeeded", actor_user=self.user)
        return data


class AuditedTokenObtainPairView(TokenObtainPairView):
    serializer_class = AuditedTokenObtainPairSerializer
    throttle_scope = 'login'


class VersionedTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        refresh = self.token_class(attrs['refresh'])
        try:
            user_id = refresh[jwt_api_settings.USER_ID_CLAIM]
            token_version = int(refresh['token_version'])
            user = get_user_model().objects.get(
                **{jwt_api_settings.USER_ID_FIELD: user_id}
            )
        except (KeyError, TypeError, ValueError, get_user_model().DoesNotExist) as exc:
            raise AuthenticationFailed(
                'This refresh token is no longer valid. Please sign in again.',
                code='token_revoked',
            ) from exc

        current_version, _ = AuthTokenVersion.objects.get_or_create(user=user)
        password_hash = refresh.get(jwt_api_settings.REVOKE_TOKEN_CLAIM)
        if (
            token_version != current_version.version
            or not hmac.compare_digest(
                password_hash or '',
                get_md5_hash_password(user.password),
            )
        ):
            record_audit(
                self.context['request'],
                'Refresh Token Denied',
                actor_user=user,
                outcome=AuditLog.Outcome.FAILURE,
                details='Refresh token was revoked or invalidated by a password change.',
            )
            raise AuthenticationFailed(
                'This refresh token is no longer valid. Please sign in again.',
                code='token_revoked',
            )
        return super().validate(attrs)


class VersionedTokenRefreshView(TokenRefreshView):
    serializer_class = VersionedTokenRefreshSerializer


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        with transaction.atomic():
            token_version, _ = AuthTokenVersion.objects.select_for_update().get_or_create(
                user=request.user
            )
            AuthTokenVersion.objects.filter(pk=token_version.pk).update(
                version=F('version') + 1
            )
        record_audit(
            request,
            'Sessions Revoked',
            details='All previously issued access and refresh tokens were revoked.',
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class AccountView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({
            'username': request.user.get_username(),
            'email': request.user.email,
            'is_staff': request.user.is_staff,
        })


class AdminOverviewView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        now = timezone.now()
        search = request.query_params.get('search', '').strip()
        try:
            page = int(request.query_params.get('page', 1))
            page_size = min(max(int(request.query_params.get('page_size', 50)), 1), 100)
        except ValueError as exc:
            raise ValidationError(
                {'page': 'Page and page_size must be whole numbers.'}
            ) from exc
        if page < 1:
            raise ValidationError({'page': 'Page must be at least 1.'})
        users = User.objects.order_by('-date_joined', '-pk')
        if search:
            users = users.filter(
                Q(username__icontains=search) | Q(email__icontains=search)
            )
        user_count = users.count()
        user_page_count = (user_count + page_size - 1) // page_size
        if user_page_count and page > user_page_count:
            raise NotFound('Account page not found.')
        user_start = (page - 1) * page_size
        user_rows = list(users[user_start:user_start + page_size])
        user_ids = [user.pk for user in user_rows]
        moderation_by_user = {
            entry.user_id: entry
            for entry in UserModeration.objects.filter(user_id__in=user_ids)
        }
        file_counts = dict(
            SecureFile.objects.filter(user_id__in=user_ids)
            .values_list('user_id')
            .annotate(total=Count('id'))
        )
        accounts = []
        for user in user_rows:
            moderation = moderation_by_user.get(user.pk)
            timed_out = bool(
                user.is_active
                and moderation
                and moderation.suspended_until
                and moderation.suspended_until > now
            )
            accounts.append({
                'id': user.pk,
                'username': user.get_username(),
                'email': user.email,
                'date_joined': user.date_joined,
                'last_login': user.last_login,
                'is_active': user.is_active,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
                'file_count': file_counts.get(user.pk, 0),
                'warning_count': moderation.warning_count if moderation else 0,
                'suspended_until': (
                    moderation.suspended_until if moderation else None
                ),
                'last_note': moderation.last_note if moderation else '',
                'timed_out': timed_out,
                'protected_admin': user.is_staff or user.is_superuser,
            })

        return Response({
            'counts': {
                'users': User.objects.count(),
                'active_users': User.objects.filter(is_active=True).count(),
                'blocked_users': User.objects.filter(is_active=False).count(),
                'timed_out_users': UserModeration.objects.filter(
                    suspended_until__gt=now,
                    user__is_active=True,
                ).count(),
                'documents': SecureFile.objects.count(),
                'shares': FileShare.objects.count(),
                'audit_events': AuditLog.objects.count(),
                'recent_events_24h': AuditLog.objects.filter(
                    timestamp__gte=now - timedelta(hours=24)
                ).count(),
            },
            'users': accounts,
            'users_truncated': page < user_page_count,
            'users_page': page,
            'users_page_count': user_page_count,
            'users_count': user_count,
        })


class AdminUserActionView(APIView):
    permission_classes = [permissions.IsAdminUser]

    @transaction.atomic
    def post(self, request, pk):
        try:
            target = User.objects.select_for_update().get(pk=pk)
        except User.DoesNotExist as exc:
            raise NotFound('Account not found.') from exc

        if target.pk == request.user.pk:
            raise ValidationError({'user': 'You cannot moderate your own admin account.'})
        if target.is_staff or target.is_superuser:
            raise ValidationError(
                {'user': 'Admin accounts are protected from moderation actions.'}
            )

        serializer = AdminModerationActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        action_name = serializer.validated_data['action']
        note = serializer.validated_data.get('note', '').strip()
        now = timezone.now()
        moderation, _ = UserModeration.objects.select_for_update().get_or_create(
            user=target
        )
        audit_action = 'Admin User Action'

        if action_name == 'warn':
            moderation.warning_count += 1
            moderation.last_note = note
            moderation.updated_by = request.user
            moderation.save(
                update_fields=[
                    'warning_count',
                    'last_note',
                    'updated_by',
                    'updated_at',
                ]
            )
            audit_action = 'Admin User Warned'
        elif action_name == 'timeout':
            if not target.is_active:
                raise ValidationError(
                    {'user': 'Unblock this account before applying a timeout.'}
                )
            until = now + timedelta(
                minutes=serializer.validated_data['duration_minutes']
            )
            moderation.suspended_until = until
            moderation.last_note = note
            moderation.updated_by = request.user
            moderation.save(
                update_fields=[
                    'suspended_until',
                    'last_note',
                    'updated_by',
                    'updated_at',
                ]
            )
            audit_action = 'Admin User Timed Out'
        elif action_name == 'clear_timeout':
            moderation.suspended_until = None
            moderation.last_note = note
            moderation.updated_by = request.user
            moderation.save(
                update_fields=[
                    'suspended_until',
                    'last_note',
                    'updated_by',
                    'updated_at',
                ]
            )
            audit_action = 'Admin User Timeout Cleared'
        else:
            target.is_active = action_name == 'unblock'
            target.save(update_fields=['is_active'])
            if action_name == 'unblock':
                moderation.suspended_until = None
                audit_action = 'Admin User Unblocked'
            else:
                moderation.suspended_until = None
                audit_action = 'Admin User Blocked'
            moderation.last_note = note
            moderation.updated_by = request.user
            moderation.save(
                update_fields=[
                    'suspended_until',
                    'last_note',
                    'updated_by',
                    'updated_at',
                ]
            )

        if action_name in ('timeout', 'clear_timeout', 'block', 'unblock'):
            token_version, _ = AuthTokenVersion.objects.get_or_create(user=target)
            AuthTokenVersion.objects.filter(pk=token_version.pk).update(
                version=F('version') + 1
            )

        record_audit(
            request,
            audit_action,
            actor_user=request.user,
            actor_username=request.user.get_username(),
            details=(
                f"Target account: {target.get_username()}; action: {action_name}; "
                f"note: {note or 'none'}."
            ),
        )
        return Response({'message': f'Action {action_name} applied.'})


class AdminAuditView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        try:
            limit = min(max(int(request.query_params.get('limit', 100)), 1), 500)
        except ValueError as exc:
            raise ValidationError({'limit': 'Limit must be a whole number.'}) from exc
        queryset = AuditLog.objects.select_related(
            'user',
            'file',
            'file_owner',
        ).order_by('-timestamp')
        search = request.query_params.get('search', '').strip()
        if search:
            queryset = queryset.filter(
                Q(actor_username__icontains=search)
                | Q(file_title__icontains=search)
                | Q(file_owner_username__icontains=search)
                | Q(action__icontains=search)
                | Q(details__icontains=search)
            )
        return Response(AuditLogSerializer(queryset[:limit], many=True).data)


class ActivitySummaryView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        now = timezone.now()
        activity = AuditLog.objects.filter(
            Q(user=request.user) | Q(file_owner=request.user)
        )
        return Response({
            'count_24h': activity.filter(
                timestamp__gte=now - timedelta(hours=24)
            ).count(),
            'events': AuditLogSerializer(
                activity.select_related('user', 'file', 'file_owner')
                .order_by('-timestamp')[:50],
                many=True,
            ).data,
        })


class AdminDocumentListView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        try:
            page = int(request.query_params.get('page', 1))
            page_size = min(max(int(request.query_params.get('page_size', 50)), 1), 100)
        except ValueError as exc:
            raise ValidationError(
                {'page': 'Page and page_size must be whole numbers.'}
            ) from exc
        if page < 1:
            raise ValidationError({'page': 'Page must be at least 1.'})

        queryset = SecureFile.objects.select_related('user').prefetch_related(
            'shares__recipient',
            'shared_revisions',
        ).order_by('-uploaded_at', '-pk')
        search = request.query_params.get('search', '').strip()
        owner = request.query_params.get('owner', '').strip()
        category = request.query_params.get('category', '').strip()
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search)
                | Q(category__icontains=search)
                | Q(user__username__icontains=search)
            )
        if owner:
            queryset = queryset.filter(user__username__icontains=owner)
        if category:
            queryset = queryset.filter(category__icontains=category)

        count = queryset.count()
        page_count = (count + page_size - 1) // page_size
        if page_count and page > page_count:
            raise NotFound('Document page not found.')
        start = (page - 1) * page_size
        documents = queryset[start:start + page_size]
        record_audit(
            request,
            'Admin Document Inventory Viewed',
            details=(
                f'Page {page}; search={search or "none"}; '
                f'results={len(documents)} of {count}; documents='
                + ', '.join(
                    f'{document.pk}:{document.title}' for document in documents
                )
                + '.'
            ),
        )
        return Response({
            'count': count,
            'page': page,
            'page_size': page_size,
            'page_count': page_count,
            'results': AdminSecureFileSerializer(documents, many=True).data,
        })


class AdminDocumentDetailView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get_object(self, pk):
        try:
            return SecureFile.objects.select_related('user').get(pk=pk)
        except SecureFile.DoesNotExist as exc:
            raise NotFound('Document not found.') from exc

    def patch(self, request, pk):
        secure_file = self.get_object(pk)
        serializer = AdminSecureFileUpdateSerializer(
            secure_file,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        changed = [
            field
            for field, before in (
                ('title', secure_file.title),
                ('category', secure_file.category),
            )
            if field in serializer.validated_data
            and serializer.validated_data[field] != before
        ]
        secure_file = serializer.save()
        record_audit(
            request,
            'Document Metadata Updated by Admin',
            file=secure_file,
            details=(
                f'Updated document fields: {", ".join(changed)}.'
                if changed
                else 'Administrator submitted unchanged document metadata.'
            ),
        )
        return Response(AdminSecureFileSerializer(secure_file).data)

    def delete(self, request, pk):
        secure_file = self.get_object(pk)
        delete_secure_file(request, secure_file, action='File Deleted by Admin')
        return Response(status=status.HTTP_204_NO_CONTENT)


class AdminDocumentDownloadView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request, pk):
        try:
            secure_file = SecureFile.objects.get(pk=pk)
        except SecureFile.DoesNotExist as exc:
            raise NotFound('Document not found.') from exc
        return build_file_download_response(
            request,
            secure_file,
            action='File Downloaded by Admin',
        )


class AdminDocumentReplaceView(APIView):
    permission_classes = [permissions.IsAdminUser]

    @transaction.atomic
    def post(self, request, pk):
        try:
            secure_file = SecureFile.objects.select_for_update().get(pk=pk)
        except SecureFile.DoesNotExist as exc:
            raise NotFound('Document not found.') from exc
        serializer = AdminSecureFileReplacementSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        uploaded_file = serializer.validated_data['file']
        try:
            encrypted_file = encrypt_file(uploaded_file)
        except ImproperlyConfigured as exc:
            raise EncryptionUnavailable() from exc

        old_file = secure_file.file
        old_name = old_file.name
        old_storage = old_file.storage
        stored_name = None
        try:
            stored_name = old_storage.save(
                f'encrypted_vault/{uuid.uuid4().hex}.enc',
                File(encrypted_file),
            )
            secure_file.file.name = stored_name
            secure_file.title = uploaded_file.name
            secure_file.file_size = uploaded_file.size
            secure_file.encryption_algorithm = 'AES-256-GCM'
            secure_file.encryption_version = 1
            secure_file.save(update_fields=[
                'file',
                'title',
                'file_size',
                'encryption_algorithm',
                'encryption_version',
            ])
            record_audit(
                request,
                'File Replaced by Admin',
                file=secure_file,
                details=f'Administrator replaced the document contents with {uploaded_file.name}.',
            )
        except Exception:
            if stored_name:
                old_storage.delete(stored_name)
            raise
        finally:
            encrypted_file.close()

        if old_name and old_name != stored_name:
            transaction.on_commit(lambda: old_storage.delete(old_name))
        return Response(AdminSecureFileSerializer(secure_file).data)


class AdminShareActionView(APIView):
    permission_classes = [permissions.IsAdminUser]

    @transaction.atomic
    def post(self, request, pk):
        try:
            share = FileShare.objects.select_for_update().select_related(
                'file',
                'recipient',
            ).get(pk=pk)
        except FileShare.DoesNotExist as exc:
            raise NotFound('Share not found.') from exc
        action_name = request.data.get('action')
        if action_name != 'revoke':
            raise ValidationError({'action': 'Only the revoke action is supported.'})
        if share.revoked_at is None:
            share.revoked_at = timezone.now()
            share.save(update_fields=['revoked_at'])
            record_audit(
                request,
                'File Share Revoked by Admin',
                file=share.file,
                details=(
                    f'Administrator revoked access for {share.recipient.get_username()}.'
                ),
            )
        return Response({'message': 'Share access revoked.'})


class EncryptionUnavailable(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = (
        "File encryption is not configured. Set FILE_ENCRYPTION_KEY and restart the API."
    )
    default_code = "encryption_unavailable"


def active_shares():
    now = timezone.now()
    return FileShare.objects.filter(revoked_at__isnull=True).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=now)
    )


def filter_documents(
    queryset,
    request,
    *,
    owner_field,
    title_field='title',
    category_field='category',
    uploaded_at_field='uploaded_at',
):
    params = request.query_params
    search = params.get('search', '').strip()
    if search:
        queryset = queryset.filter(
            Q(**{f'{title_field}__icontains': search})
            | Q(**{f'{category_field}__icontains': search})
            | Q(**{f'{owner_field}__icontains': search})
        )

    owner = params.get('owner', '').strip()
    if owner:
        queryset = queryset.filter(**{f'{owner_field}__icontains': owner})

    category = params.get('category', '').strip()
    if category:
        queryset = queryset.filter(**{f'{category_field}__iexact': category})

    for parameter, lookup in (
        ('date_from', f'{uploaded_at_field}__date__gte'),
        ('date_to', f'{uploaded_at_field}__date__lte'),
    ):
        value = params.get(parameter)
        if value:
            try:
                parsed = parse_date(value)
            except ValueError:
                parsed = None
            if parsed is None:
                raise ValidationError(
                    {parameter: "Use a valid date in YYYY-MM-DD format."}
                )
            queryset = queryset.filter(**{lookup: parsed})

    return queryset


def build_file_download_response(
    request,
    secure_file,
    *,
    action='File Downloaded',
):
    return build_stored_download_response(
        request,
        stored_file=secure_file.file,
        encryption_version=secure_file.encryption_version,
        title=secure_file.title,
        audit_file=secure_file,
        action=action,
    )


def build_stored_download_response(
    request,
    *,
    stored_file,
    encryption_version,
    title,
    audit_file,
    action,
):
    try:
        file_handle = stored_file.open('rb')
        if encryption_version == 1:
            with file_handle:
                file_handle = decrypt_file(file_handle)
        elif encryption_version != 0:
            file_handle.close()
            raise APIException("This file uses an unsupported encryption format.")
    except ImproperlyConfigured as exc:
        record_audit(
            request,
            f"{action} Failed",
            file=audit_file,
            outcome=AuditLog.Outcome.FAILURE,
            details="File encryption configuration is unavailable.",
        )
        raise EncryptionUnavailable() from exc
    except (InvalidTag, InvalidEncryptedFile) as exc:
        logger.exception("Could not verify encrypted file %s.", audit_file.pk)
        record_audit(
            request,
            f"{action} Failed",
            file=audit_file,
            outcome=AuditLog.Outcome.FAILURE,
            details="Stored file integrity verification failed.",
        )
        raise APIException("The stored file could not be safely decrypted.") from exc

    record_audit(request, action, file=audit_file)
    return FileResponse(file_handle, as_attachment=True, filename=title)


def delete_secure_file(request, secure_file, *, action="File Deleted"):
    stored_files = [(secure_file.file.storage, secure_file.file.name)]
    stored_files.extend(
        (revision.file.storage, revision.file.name)
        for revision in secure_file.shared_revisions.all()
    )
    for storage, name in stored_files:
        if name:
            storage.delete(name)

    record_audit(
        request,
        action,
        file=secure_file,
        details=f"Deleted file and shared copies: {secure_file.title}",
    )
    secure_file.delete()


def delete_file_share(request, share):
    for revision in share.revisions.all():
        if revision.file.name:
            revision.file.storage.delete(revision.file.name)
    record_audit(
        request,
        "File Share Deleted by Admin",
        file=share.file,
        details=f"Admin removed the share for {share.recipient.username}.",
    )
    share.delete()


def authorize_shared_file(request, share, passcode):
    failure = None
    secure_file = None
    with transaction.atomic():
        locked_share = active_shares().select_for_update().filter(
            pk=share.pk,
            recipient=request.user,
        ).first()
        if locked_share is None:
            record_audit(
                request,
                "Shared File Access Denied",
                file=share.file,
                outcome=AuditLog.Outcome.FAILURE,
                details="Share was revoked or expired during access authorization.",
            )
            failure = NotFound()
        else:
            secure_file = SecureFile.objects.select_for_update().filter(
                pk=locked_share.file_id
            ).first()
            if secure_file is None:
                record_audit(
                    request,
                    "Shared File Access Denied",
                    file=None,
                    outcome=AuditLog.Outcome.FAILURE,
                    details="Shared file no longer exists.",
                )
                failure = NotFound()
            elif (
                locked_share.passcode_locked_until
                and locked_share.passcode_locked_until > timezone.now()
            ):
                record_audit(
                    request,
                    "File Passcode Locked",
                    file=secure_file,
                    outcome=AuditLog.Outcome.FAILURE,
                    details="Shared file access was blocked by the PIN lockout.",
                )
                failure = Throttled(
                    wait=(
                        locked_share.passcode_locked_until - timezone.now()
                    ).total_seconds()
                )
            elif not secure_file.passcode_hash:
                record_audit(
                    request,
                    "File Download Denied",
                    file=secure_file,
                    outcome=AuditLog.Outcome.FAILURE,
                    details="File owner has not set a PIN.",
                )
                failure = PermissionDenied(
                    "The file owner must set a passcode before this file can be accessed."
                )
            elif not check_password(passcode, secure_file.passcode_hash):
                locked_share.failed_passcode_attempts += 1
                locked = (
                    locked_share.failed_passcode_attempts >= MAX_PASSCODE_ATTEMPTS
                )
                if locked:
                    locked_share.failed_passcode_attempts = 0
                    locked_share.passcode_locked_until = (
                        timezone.now() + PASSCODE_LOCKOUT
                    )
                locked_share.save(
                    update_fields=[
                        'failed_passcode_attempts',
                        'passcode_locked_until',
                    ]
                )
                record_audit(
                    request,
                    "File Passcode Lockout" if locked else "File Passcode Failed",
                    file=secure_file,
                    outcome=AuditLog.Outcome.FAILURE,
                    details=(
                        "Share locked for 15 minutes after repeated failed PIN attempts."
                        if locked
                        else "Shared file access was attempted with an incorrect PIN."
                    ),
                )
                failure = (
                    Throttled(wait=PASSCODE_LOCKOUT.total_seconds())
                    if locked
                    else PermissionDenied("Incorrect file PIN.")
                )
            else:
                locked_share.failed_passcode_attempts = 0
                locked_share.passcode_locked_until = None
                locked_share.save(
                    update_fields=[
                        'failed_passcode_attempts',
                        'passcode_locked_until',
                    ]
                )

    if failure is not None:
        raise failure
    return secure_file


def replace_shared_original(request, share, uploaded_file, passcode):
    failure = None
    secure_file = None
    storage = None
    old_name = None
    stored_name = None
    try:
        with transaction.atomic():
            locked_share = active_shares().select_for_update().filter(
                pk=share.pk,
                recipient=request.user,
                permission=FileShare.Permission.EDIT,
                can_replace_original=True,
            ).first()
            if locked_share is None:
                record_audit(
                    request,
                    "Shared File Replacement Denied",
                    file=share.file,
                    outcome=AuditLog.Outcome.FAILURE,
                    details="The owner has not granted active edit access for this share.",
                )
                failure = PermissionDenied(
                    "The document owner must grant edit access before the original can be replaced."
                )
            else:
                secure_file = authorize_shared_file(request, locked_share, passcode)
                old_file = secure_file.file
                old_name = old_file.name
                storage = old_file.storage
                try:
                    encrypted_file = encrypt_file(uploaded_file)
                except ImproperlyConfigured as exc:
                    raise EncryptionUnavailable() from exc

                try:
                    stored_name = storage.save(
                        f"encrypted_vault/{uuid.uuid4().hex}.enc",
                        File(encrypted_file),
                    )
                    secure_file.file.name = stored_name
                    secure_file.title = uploaded_file.name
                    secure_file.file_size = uploaded_file.size
                    secure_file.encryption_algorithm = "AES-256-GCM"
                    secure_file.encryption_version = 1
                    secure_file.save(
                        update_fields=[
                            'file',
                            'title',
                            'file_size',
                            'encryption_algorithm',
                            'encryption_version',
                        ]
                    )
                finally:
                    encrypted_file.close()

                record_audit(
                    request,
                    "Shared File Replaced",
                    file=secure_file,
                    details=(
                        f"Recipient {request.user.get_username()} replaced the original "
                        f"file contents with {uploaded_file.name}."
                    ),
                )
    except Exception:
        if stored_name and storage:
            storage.delete(stored_name)
        raise

    if failure is not None:
        raise failure
    if old_name and stored_name and old_name != stored_name:
        storage.delete(old_name)
    return secure_file


def record_passcode_failure(request, share, details):
    now = timezone.now()
    with transaction.atomic():
        share = FileShare.objects.select_for_update().select_related('file').get(
            pk=share.pk
        )
        if share.passcode_locked_until and share.passcode_locked_until > now:
            record_audit(
                request,
                "File Passcode Locked",
                file=share.file,
                outcome=AuditLog.Outcome.FAILURE,
                details="Download was blocked by the passcode lockout.",
            )
            return Throttled(wait=(share.passcode_locked_until - now).total_seconds())

        share.failed_passcode_attempts += 1
        locked = share.failed_passcode_attempts >= MAX_PASSCODE_ATTEMPTS
        if locked:
            share.failed_passcode_attempts = 0
            share.passcode_locked_until = now + PASSCODE_LOCKOUT
        share.save(
            update_fields=['failed_passcode_attempts', 'passcode_locked_until']
        )
        record_audit(
            request,
            "File Passcode Lockout" if locked else "File Passcode Failed",
            file=share.file,
            outcome=AuditLog.Outcome.FAILURE,
            details=(
                "Share locked for 15 minutes after repeated failed PIN attempts."
                if locked
                else details
            ),
        )
    if locked:
        return Throttled(wait=PASSCODE_LOCKOUT.total_seconds())
    return PermissionDenied("Incorrect file PIN.")


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_scope = 'register'

    def post(self, request):
        with transaction.atomic():
            serializer = RegisterSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            record_audit(
                request,
                "User Registered",
                actor_user=user,
                details="Account created.",
            )
        return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)


class SecureFileViewSet(viewsets.ModelViewSet):
    queryset = SecureFile.objects.all()
    serializer_class = SecureFileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = self.queryset.filter(user=self.request.user)
        return filter_documents(
            queryset,
            self.request,
            owner_field='user__username',
        )

    def perform_create(self, serializer):
        file_obj = serializer.validated_data['file']
        try:
            encrypted_file = encrypt_file(file_obj)
        except ImproperlyConfigured as exc:
            raise EncryptionUnavailable() from exc
        try:
            instance = serializer.save(
                user=self.request.user,
                file=File(encrypted_file, name=f"{uuid.uuid4().hex}.enc"),
                file_size=file_obj.size,
                encryption_algorithm="AES-256-GCM",
                encryption_version=1,
            )
        finally:
            encrypted_file.close()

        record_audit(self.request, "File Uploaded", file=instance)

    def perform_update(self, serializer):
        file_obj = serializer.validated_data.get('file')
        previous_title = serializer.instance.title
        previous_category = serializer.instance.category
        if file_obj is None:
            instance = serializer.save()
            changed_fields = [
                field
                for field, before, after in (
                    ('title', previous_title, instance.title),
                    ('category', previous_category, instance.category),
                )
                if before != after
            ]
            record_audit(
                self.request,
                "Document Metadata Updated" if changed_fields else "Document Updated",
                file=instance,
                details=(
                    f"Updated document fields: {', '.join(changed_fields)}."
                    if changed_fields
                    else ""
                ),
            )
        else:
            old_file = serializer.instance.file
            old_file_name = old_file.name
            old_file_storage = old_file.storage
            try:
                encrypted_file = encrypt_file(file_obj)
            except ImproperlyConfigured as exc:
                raise EncryptionUnavailable() from exc
            try:
                instance = serializer.save(
                    file=File(encrypted_file, name=f"{uuid.uuid4().hex}.enc"),
                    file_size=file_obj.size,
                    encryption_algorithm="AES-256-GCM",
                    encryption_version=1,
                )
            finally:
                encrypted_file.close()

            if old_file_name != instance.file.name:
                old_file_storage.delete(old_file_name)
            record_audit(self.request, "File Updated", file=instance)

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        secure_file = self.get_object()
        return build_file_download_response(request, secure_file)

    def perform_destroy(self, instance):
        delete_secure_file(self.request, instance)

    def retrieve(self, request, *args, **kwargs):
        secure_file = self.get_object()
        serializer = self.get_serializer(secure_file)
        record_audit(request, "File Viewed", file=secure_file)
        return Response(serializer.data)

    def get_object(self):
        try:
            return super().get_object()
        except Http404:
            if self.request.user.is_authenticated:
                lookup = self.kwargs.get(self.lookup_url_kwarg or self.lookup_field)
                try:
                    secure_file = SecureFile.objects.filter(pk=lookup).first()
                except (TypeError, ValueError):
                    secure_file = None
                record_audit(
                    self.request,
                    "File Access Denied",
                    file=secure_file,
                    outcome=AuditLog.Outcome.FAILURE,
                    details="Authenticated user attempted an unavailable or unauthorized file action.",
                )
            raise

    @action(detail=True, methods=['put', 'delete'])
    def passcode(self, request, pk=None):
        secure_file = self.get_object()
        if request.method == 'PUT':
            serializer = FilePasscodeSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            secure_file.passcode_hash = make_password(
                serializer.validated_data['passcode']
            )
            secure_file.save(update_fields=['passcode_hash'])
            secure_file.shares.update(
                failed_passcode_attempts=0,
                passcode_locked_until=None,
            )
            record_audit(
                request,
                "File Passcode Set",
                file=secure_file,
            )
            return Response({'has_passcode': True})

        secure_file.passcode_hash = ''
        secure_file.save(update_fields=['passcode_hash'])
        now = timezone.now()
        for share in active_shares().filter(file=secure_file).select_related('recipient'):
            share.revoked_at = now
            share.save(update_fields=['revoked_at'])
            record_audit(
                request,
                "File Share Revoked",
                file=secure_file,
                details=f"Access revoked for {share.recipient.username} after PIN removal.",
            )
        record_audit(
            request,
            "File Passcode Removed",
            file=secure_file,
        )
        return Response({'has_passcode': False})

    @action(detail=True, methods=['get', 'post'])
    def share(self, request, pk=None):
        secure_file = self.get_object()
        if request.method == 'GET':
            shares = secure_file.shares.select_related('recipient').order_by('-created_at')
            record_audit(request, "File Shares Viewed", file=secure_file)
            return Response(FileShareSerializer(shares, many=True).data)

        serializer = FileShareCreateSerializer(
            data=request.data,
            context={'request': request, 'file': secure_file},
        )
        if not serializer.is_valid():
            record_audit(
                request,
                "File Share Failed",
                file=secure_file,
                outcome=AuditLog.Outcome.FAILURE,
                details="Share request was rejected by validation.",
            )
            raise ValidationError(serializer.errors)
        recipient = serializer.validated_data['recipient']
        share, created = FileShare.objects.update_or_create(
            file=secure_file,
            recipient=recipient,
            defaults={
                'expires_at': serializer.validated_data.get('expires_at'),
                'revoked_at': None,
                'permission': serializer.validated_data['permission'],
                'can_replace_original': (
                    serializer.validated_data['permission'] == FileShare.Permission.EDIT
                ),
                'failed_passcode_attempts': 0,
                'passcode_locked_until': None,
            },
        )
        record_audit(
            request,
            "File Shared" if created else "File Share Updated",
            file=secure_file,
            details=(
                f"Recipient: {recipient.username}; "
                f"permission: {share.permission}; "
                f"original replacement {'granted' if share.can_replace_original else 'not granted'}."
            ),
        )
        response_status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        return Response(FileShareSerializer(share).data, status=response_status)

    @action(detail=True, methods=['get'])
    def revisions(self, request, pk=None):
        secure_file = self.get_object()
        revisions = secure_file.shared_revisions.select_related(
            'editor'
        ).order_by('-created_at')
        record_audit(request, "Shared Copies Viewed", file=secure_file)
        return Response(SharedFileRevisionSerializer(revisions, many=True).data)


class FileShareViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = FileShareSerializer

    def get_queryset(self):
        return FileShare.objects.filter(file__user=self.request.user).select_related(
            'file',
            'recipient',
        )

    def list(self, request):
        shares = self.get_queryset().order_by('-created_at')
        return Response(FileShareSerializer(shares, many=True).data)

    def destroy(self, request, pk=None):
        share = self.get_object()
        if share.revoked_at is None:
            share.revoked_at = timezone.now()
            share.save(update_fields=['revoked_at'])
            record_audit(
                request,
                "File Share Revoked",
                file=share.file,
                details=f"Access revoked for {share.recipient.username}.",
            )
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_object(self):
        try:
            return super().get_object()
        except Http404:
            if self.request.user.is_authenticated:
                lookup = self.kwargs.get(self.lookup_url_kwarg or self.lookup_field)
                try:
                    share = FileShare.objects.select_related('file').filter(pk=lookup).first()
                except (TypeError, ValueError):
                    share = None
                record_audit(
                    self.request,
                    "File Share Access Denied",
                    file=share.file if share else None,
                    outcome=AuditLog.Outcome.FAILURE,
                    details="Authenticated user attempted to access or revoke an unavailable share.",
                )
            raise


class SharedFileViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SharedFileSerializer

    def get_queryset(self):
        queryset = active_shares().filter(recipient=self.request.user).select_related(
            'file',
            'file__user',
        )
        queryset = filter_documents(
            queryset,
            self.request,
            owner_field='file__user__username',
            title_field='file__title',
            category_field='file__category',
            uploaded_at_field='file__uploaded_at',
        )
        return queryset.order_by('-created_at')

    @action(detail=True, methods=['post'])
    def download(self, request, pk=None):
        lookup = self.kwargs.get(self.lookup_url_kwarg or self.lookup_field)
        try:
            share = FileShare.objects.select_related('file').filter(pk=lookup).first()
        except (TypeError, ValueError):
            share = None

        if share is None or share.recipient_id != request.user.pk:
            record_audit(
                request,
                "Shared File Access Denied",
                file=share.file if share else None,
                outcome=AuditLog.Outcome.FAILURE,
                details="Authenticated user attempted to access an unavailable share.",
            )
            raise NotFound()

        if share.revoked_at is not None or (
            share.expires_at is not None and share.expires_at <= timezone.now()
        ):
            record_audit(
                request,
                "Shared File Access Denied",
                file=share.file,
                outcome=AuditLog.Outcome.FAILURE,
                details="Download was attempted using a revoked or expired share.",
            )
            raise NotFound()

        serializer = PasscodeEntrySerializer(data=request.data)
        if not serializer.is_valid():
            failure = record_passcode_failure(
                request,
                share,
                "Download was attempted with a malformed PIN.",
            )
            if isinstance(failure, Throttled):
                raise failure
            raise ValidationError(serializer.errors)

        secure_file = authorize_shared_file(
            request,
            share,
            serializer.validated_data['passcode'],
        )
        return build_file_download_response(request, secure_file)

    @action(detail=True, methods=['get'])
    def revisions(self, request, pk=None):
        share = self.get_object()
        revisions = share.revisions.filter(
            editor=request.user
        ).select_related('editor').order_by('-created_at')
        return Response(SharedFileRevisionSerializer(revisions, many=True).data)

    @action(detail=True, methods=['post'])
    def replace(self, request, pk=None):
        share = self.get_object()
        if share.permission != FileShare.Permission.EDIT:
            record_audit(
                request,
                "Shared File Replacement Denied",
                file=share.file,
                outcome=AuditLog.Outcome.FAILURE,
                details="The recipient has view-only access.",
            )
            raise PermissionDenied("This share grants view-only access.")

        serializer = SharedFileRevisionCreateSerializer(data=request.data)
        if not serializer.is_valid():
            if 'passcode' in serializer.errors:
                failure = record_passcode_failure(
                    request,
                    share,
                    "Uploading an edited copy was attempted with a malformed PIN.",
                )
                if isinstance(failure, Throttled):
                    raise failure
            raise ValidationError(serializer.errors)
        secure_file = replace_shared_original(
            request,
            share,
            serializer.validated_data['file'],
            serializer.validated_data['passcode'],
        )
        return Response(
            {
                'file_id': secure_file.pk,
                'title': secure_file.title,
                'file_size': secure_file.file_size,
                'replaced': True,
            }
        )


class SharedFileRevisionViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SharedFileRevisionSerializer

    def get_queryset(self):
        return SharedFileRevision.objects.filter(
            Q(source_file__user=self.request.user)
            | Q(
                share__in=active_shares().filter(
                    recipient=self.request.user,
                    permission=FileShare.Permission.EDIT,
                ),
                editor=self.request.user,
            )
        ).select_related('source_file', 'editor')

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        revision = self.get_object()
        return build_stored_download_response(
            request,
            stored_file=revision.file,
            encryption_version=revision.encryption_version,
            title=revision.title,
            audit_file=revision.source_file,
            action="Shared Copy Downloaded",
        )

    def get_object(self):
        try:
            return super().get_object()
        except Http404:
            lookup = self.kwargs.get(self.lookup_url_kwarg or self.lookup_field)
            revision = SharedFileRevision.objects.select_related(
                'source_file'
            ).filter(pk=lookup).first()
            record_audit(
                self.request,
                "Shared Copy Access Denied",
                file=revision.source_file if revision else None,
                outcome=AuditLog.Outcome.FAILURE,
                details="Authenticated user attempted to access an unavailable shared copy.",
            )
            raise


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AuditLog.objects.filter(
            Q(user=self.request.user) | Q(file_owner=self.request.user)
        ).select_related('user', 'file', 'file_owner').order_by('-timestamp')

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import get_md5_hash_password
from django.utils import timezone

from .models import AuditLog, AuthTokenVersion, UserModeration


class VersionedJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        self._failed_user = None
        try:
            return super().authenticate(request)
        except AuthenticationFailed:
            if self._failed_user is not None:
                from .views import record_audit

                record_audit(
                    request,
                    'Authentication Denied',
                    actor_user=self._failed_user,
                    outcome=AuditLog.Outcome.FAILURE,
                    details=(
                        f'{request.method} {request.path_info} used a revoked token.'
                    ),
                )
            raise

    def get_user(self, validated_token):
        try:
            user_id = validated_token[api_settings.USER_ID_CLAIM]
        except KeyError as exc:
            raise AuthenticationFailed(
                'Token contained no recognizable user identification.',
                code='token_not_valid',
            ) from exc

        try:
            user = self.user_model.objects.get(
                **{api_settings.USER_ID_FIELD: user_id}
            )
        except self.user_model.DoesNotExist as exc:
            raise AuthenticationFailed(
                'User not found.',
                code='user_not_found',
            ) from exc

        self._failed_user = user
        if api_settings.CHECK_USER_IS_ACTIVE and not user.is_active:
            raise AuthenticationFailed('User is inactive.', code='user_inactive')
        moderation = UserModeration.objects.filter(user=user).first()
        if moderation and moderation.suspended_until and moderation.suspended_until > timezone.now():
            raise AuthenticationFailed(
                'This account is temporarily suspended until '
                f'{moderation.suspended_until.isoformat()}.',
                code='user_suspended',
            )
        if api_settings.CHECK_REVOKE_TOKEN:
            if validated_token.get(
                api_settings.REVOKE_TOKEN_CLAIM
            ) != get_md5_hash_password(user.password):
                raise AuthenticationFailed(
                    'The user password has changed.',
                    code='password_changed',
                )

        try:
            token_version = int(validated_token['token_version'])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationFailed(
                'This token is no longer valid. Please sign in again.',
                code='token_revoked',
            ) from exc

        current_version, _ = AuthTokenVersion.objects.get_or_create(user=user)
        if token_version != current_version.version:
            raise AuthenticationFailed(
                'This token is no longer valid. Please sign in again.',
                code='token_revoked',
            )
        self._failed_user = None
        return user

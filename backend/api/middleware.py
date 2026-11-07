from urllib.parse import unquote

from rest_framework.exceptions import AuthenticationFailed

from .authentication import VersionedJWTAuthentication
from .models import AuditLog, SecureFile, SharedFileRevision


class AuditDeniedMediaRequestsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        media_request = request.path_info.startswith('/media/')
        admin_denial = (
            request.path_info.startswith('/admin/')
            and response.status_code in (401, 403, 404, 405, 429)
        )
        if (
            (media_request and response.status_code in (401, 403, 404, 405, 429))
            or admin_denial
        ):
            from .views import record_audit

            if media_request and not request.user.is_authenticated:
                try:
                    authentication = VersionedJWTAuthentication().authenticate(request)
                except AuthenticationFailed:
                    authentication = None
                if authentication is not None:
                    request.user = authentication[0]

            secure_file = None
            if media_request:
                relative_path = unquote(request.path_info[len('/media/'):])
                secure_file = SecureFile.objects.select_related('user').filter(
                    file=relative_path
                ).first()
                if secure_file is None:
                    revision = SharedFileRevision.objects.select_related(
                        'source_file__user'
                    ).filter(file=relative_path).first()
                    secure_file = revision.source_file if revision else None
            actor = request.user if request.user.is_authenticated else None
            record_audit(
                request,
                (
                    'Direct Media Access Denied'
                    if media_request
                    else 'Admin Access Denied'
                ),
                file=secure_file,
                actor_user=actor,
                outcome=AuditLog.Outcome.FAILURE,
                details=(
                    f'{request.method} {request.path_info} returned '
                    f'HTTP {response.status_code}.'
                ),
            )
        return response

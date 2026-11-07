from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver


@receiver(user_login_failed)
def audit_failed_login(sender, credentials, request=None, **kwargs):
    if request is None:
        return

    from .views import record_audit

    username = credentials.get('username') or credentials.get('email') or ''
    record_audit(
        request,
        'Login Failed',
        actor_username=username,
        outcome='failure',
        details='Account login was rejected.',
    )

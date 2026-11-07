import os

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Create the initial SV administrator from operator-provided environment values.'

    def handle(self, *args, **options):
        username = os.environ.get('SV_ADMIN_USERNAME', '').strip()
        email = os.environ.get('SV_ADMIN_EMAIL', '').strip()
        password = os.environ.get('SV_ADMIN_PASSWORD', '')
        if not username or not email or not password:
            raise CommandError(
                'Set SV_ADMIN_USERNAME, SV_ADMIN_EMAIL, and SV_ADMIN_PASSWORD '
                'in the environment before running this command.'
            )

        user_model = get_user_model()
        if user_model.objects.filter(username=username).exists():
            raise CommandError(
                f'Account "{username}" already exists; no account was changed.'
            )

        user = user_model(username=username, email=email)
        try:
            validate_password(password, user=user)
        except ValidationError as exc:
            raise CommandError('SV_ADMIN_PASSWORD does not meet password requirements.') from exc

        user_model.objects.create_superuser(
            username=username,
            email=email,
            password=password,
        )
        self.stdout.write(self.style.SUCCESS('SV administrator created.'))

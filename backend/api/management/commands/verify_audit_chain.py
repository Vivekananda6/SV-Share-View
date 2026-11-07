from django.core.management.base import BaseCommand, CommandError

from api.audit_integrity import verify_audit_chain


class Command(BaseCommand):
    help = 'Verify the audit log HMAC chain and stored chain head.'

    def handle(self, *args, **options):
        valid, message = verify_audit_chain()
        if not valid:
            raise CommandError(message)
        self.stdout.write(self.style.SUCCESS(message))

from django.db import migrations
from pathlib import Path


def create_audit_checkpoint(apps, schema_editor):
    from django.conf import settings
    from api.audit_integrity import write_audit_checkpoint_snapshot

    path = Path(settings.AUDIT_CHECKPOINT_PATH)
    if not path.exists() or path.stat().st_size == 0:
        write_audit_checkpoint_snapshot()


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_auditchainstate_auditlog_integrity_hash_and_more'),
    ]

    operations = [
        migrations.RunPython(create_audit_checkpoint, migrations.RunPython.noop),
    ]

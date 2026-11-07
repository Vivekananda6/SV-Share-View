from pathlib import Path

from django.conf import settings
from django.db import migrations


def create_audit_checkpoint_if_empty(apps, schema_editor):
    from api.audit_integrity import write_audit_checkpoint_snapshot

    path = Path(settings.AUDIT_CHECKPOINT_PATH)
    if not path.exists() or path.stat().st_size == 0:
        write_audit_checkpoint_snapshot()


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_audit_checkpoint_file'),
    ]

    operations = [
        migrations.RunPython(create_audit_checkpoint_if_empty, migrations.RunPython.noop),
    ]

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def snapshot_existing_actors(apps, schema_editor):
    AuditLog = apps.get_model("api", "AuditLog")
    alias = schema_editor.connection.alias
    for event in AuditLog.objects.using(alias).select_related("user").iterator():
        if event.user_id:
            event.actor_username = event.user.username
        AuditLog.objects.using(alias).filter(pk=event.pk).update(
            actor_username=event.actor_username,
        )


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0004_file_passcodes"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="auditlog",
            name="actor_username",
            field=models.CharField(blank=True, max_length=150),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="file_title",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="file_owner_username",
            field=models.CharField(blank=True, max_length=150),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="outcome",
            field=models.CharField(
                choices=[("success", "Success"), ("failure", "Failure")],
                default="success",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="file",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="audit_events",
                to="api.securefile",
            ),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="file_owner",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="owned_file_audit_events",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.RunPython(snapshot_existing_actors, migrations.RunPython.noop),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(fields=["-timestamp"], name="api_auditlo_timesta_96ac8f_idx"),
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(
                fields=["outcome", "-timestamp"],
                name="api_auditlo_outcome_96a70e_idx",
            ),
        ),
    ]

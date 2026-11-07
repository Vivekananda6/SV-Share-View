from django.db import migrations, models


def mark_existing_files_as_legacy(apps, schema_editor):
    SecureFile = apps.get_model("api", "SecureFile")
    SecureFile.objects.using(schema_editor.connection.alias).all().update(
        encryption_algorithm="Legacy plaintext"
    )


def restore_legacy_label(apps, schema_editor):
    SecureFile = apps.get_model("api", "SecureFile")
    SecureFile.objects.using(schema_editor.connection.alias).filter(
        encryption_algorithm="Legacy plaintext"
    ).update(encryption_algorithm="AES-256")


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="securefile",
            name="encryption_version",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="securefile",
            name="file_size",
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="securefile",
            name="encryption_algorithm",
            field=models.CharField(default="AES-256-GCM", max_length=50),
        ),
        migrations.RunPython(mark_existing_files_as_legacy, restore_legacy_label),
    ]

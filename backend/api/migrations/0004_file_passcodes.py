from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0003_file_sharing"),
    ]

    operations = [
        migrations.AddField(
            model_name="securefile",
            name="passcode_hash",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.AddField(
            model_name="fileshare",
            name="failed_passcode_attempts",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="fileshare",
            name="passcode_locked_until",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

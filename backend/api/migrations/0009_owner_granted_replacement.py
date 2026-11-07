from django.db import migrations


def grant_replacement_to_existing_edit_shares(apps, schema_editor):
    FileShare = apps.get_model('api', 'FileShare')
    FileShare.objects.filter(permission='edit').update(can_replace_original=True)


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_securefile_category'),
    ]

    operations = [
        migrations.RunPython(
            grant_replacement_to_existing_edit_shares,
            migrations.RunPython.noop,
        ),
    ]

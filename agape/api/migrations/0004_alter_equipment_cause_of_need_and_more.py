# Generated by Django 4.2.12 on 2024-11-28 06:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_alter_disabilityrecord_gender_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='equipment',
            name='cause_of_need',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='equipment',
            name='equipment_type',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='equipment',
            name='size',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]

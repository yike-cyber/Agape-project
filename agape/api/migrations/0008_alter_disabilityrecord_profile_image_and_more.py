# Generated by Django 4.2.12 on 2024-12-04 16:07

import cloudinary.models
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_alter_user_options_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='disabilityrecord',
            name='profile_image',
            field=cloudinary.models.CloudinaryField(blank=True, default='avatar_zopzfl.png', max_length=255, null=True, verbose_name='image'),
        ),
        migrations.AlterField(
            model_name='user',
            name='profile_image',
            field=cloudinary.models.CloudinaryField(blank=True, default='avatar_zopzfl.png', max_length=255, null=True, verbose_name='image'),
        ),
    ]
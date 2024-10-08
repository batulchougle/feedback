# Generated by Django 5.1.1 on 2024-09-20 11:23

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0004_jobpost'),
    ]

    operations = [
        migrations.CreateModel(
            name='Dashboard',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('work_type', models.CharField(max_length=50, verbose_name='work_type')),
                ('skills_1', models.CharField(max_length=50, verbose_name='skills_1')),
                ('skills_2', models.CharField(max_length=50, verbose_name='skills_2')),
                ('skills_3', models.CharField(max_length=50, verbose_name='skills_3')),
                ('skills_4', models.CharField(max_length=50, verbose_name='skills_4')),
                ('skills_5', models.CharField(max_length=50, verbose_name='skills_5')),
                ('title', models.CharField(max_length=150, verbose_name='title')),
                ('bio', models.TextField(verbose_name='bio')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='dashboard', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]

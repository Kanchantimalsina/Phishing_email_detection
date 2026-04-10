from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='EmailAnalysis',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sender_email', models.CharField(blank=True, max_length=255)),
                ('subject', models.CharField(blank=True, max_length=255)),
                ('email_body', models.TextField(blank=True)),
                ('source', models.CharField(default='manual', max_length=50)),
                ('verdict', models.CharField(default='safe', max_length=20)),
                ('risk_score', models.FloatField(default=0)),
                ('rule_score', models.FloatField(default=0)),
                ('ml_confidence', models.FloatField(default=0)),
                ('analysis_mode', models.CharField(default='hybrid', max_length=20)),
                ('indicators', models.JSONField(blank=True, default=list)),
                ('recommendations', models.JSONField(blank=True, default=list)),
                ('urls_found', models.JSONField(blank=True, default=list)),
                ('analyzed_at', models.DateTimeField(auto_now_add=True)),
                ('installation_id', models.CharField(db_index=True, max_length=128)),
            ],
            options={
                'ordering': ['-analyzed_at'],
            },
        ),
    ]
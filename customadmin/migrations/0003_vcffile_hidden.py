from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('customadmin', '0002_vcffile_subscription_price_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='vcffile',
            name='hidden',
            field=models.BooleanField(default=False),
        ),
    ]

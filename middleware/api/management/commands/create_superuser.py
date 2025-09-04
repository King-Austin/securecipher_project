from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.conf import settings
import os

class Command(BaseCommand):
    help = 'Create a default superuser if none exists'

    def handle(self, *args, **options):
        # Get default credentials from environment or use defaults
        username = os.getenv('DEFAULT_SUPERUSER_USERNAME', 'admin')
        password = os.getenv('DEFAULT_SUPERUSER_PASSWORD', 'securecipher')
        email = os.getenv('DEFAULT_SUPERUSER_EMAIL', 'admin@securecipher.com')

        # Check if superuser already exists
        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write(
                self.style.WARNING('Superuser already exists. Skipping creation.')
            )
            return

        # Create superuser
        try:
            User.objects.create_superuser(
                username=username,
                password=password,
                email=email
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully created superuser: {username}'
                )
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to create superuser: {str(e)}')
            )

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from commerce.db_roles import apply_roles
from commerce.models import Plan


class Command(BaseCommand):
    help = "Install sandbox catalog and restrictive database grants, as migration owner"

    def handle(self, *args, **kwargs):
        if settings.ROLE != "owner":
            raise CommandError("Schema owner role required")
        Plan.objects.get_or_create(code="sandbox-30-days", defaults={
            "name": "30 天测试方案 · 1.00 USD（模拟）", "amount_minor": 100, "currency": "USD", "term_seconds": 30 * 86400,
        })
        apply_roles()
        self.stdout.write("Sandbox catalog and database permissions are ready")

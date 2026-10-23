"""Apply privileges after migrations, as the schema owner. No application role owns tables."""
from django.db import connection


def apply_roles():
    with connection.cursor() as cursor:
        cursor.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        for role in ("xportal_web", "xportal_worker"):
            cursor.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
            cursor.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}")
            cursor.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role}")
        for table in ("commerce_account", "django_session", "commerce_ratebucket"):
            cursor.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO xportal_web")
        for table in ("commerce_checkoutrequest", "commerce_sandboxpaymentrequest"):
            cursor.execute(f"GRANT SELECT, INSERT ON {table} TO xportal_web")
        for table in ("commerce_plan", "commerce_order", "commerce_entitlement"):
            cursor.execute(f"GRANT SELECT ON {table} TO xportal_web")
        for table in ("commerce_account", "commerce_checkoutrequest", "commerce_plan", "commerce_sandboxpaymentrequest"):
            cursor.execute(f"GRANT SELECT ON {table} TO xportal_worker")
        cursor.execute("GRANT UPDATE(id) ON commerce_account TO xportal_worker")
        for table in ("commerce_order", "commerce_sandboxcharge", "commerce_paymentevent", "commerce_payment", "commerce_entitlement", "commerce_provisionjob", "commerce_ratebucket"):
            cursor.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO xportal_worker")
        # These models use UUID/text keys; service roles require no sequence privileges.

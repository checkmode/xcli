from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from commerce import paypal_api


class Command(BaseCommand):
    help = "Validate PayPal Sandbox credentials and optional webhook registration without charging"

    def handle(self, *args, **kwargs):
        if settings.ROLE not in {"worker", "owner"} or not settings.PAYPAL_ENABLED:
            raise CommandError("Enable PayPal Sandbox in a trusted process first")
        try:
            api = paypal_api.client()
            api.access_token()
            if settings.PAYPAL_WEBHOOK_ID:
                webhook_id = paypal_api.identifier(settings.PAYPAL_WEBHOOK_ID)
                value = api.request("GET", "/v1/notifications/webhooks/" + webhook_id)
                if value.get("url") != settings.PUBLIC_ORIGIN + "/webhooks/paypal/":
                    raise CommandError("Webhook URL does not match PORTAL_PUBLIC_ORIGIN/webhooks/paypal/")
                if "PAYMENT.CAPTURE.COMPLETED" not in {e.get("name") for e in value.get("event_types", [])}:
                    raise CommandError("Webhook must subscribe to PAYMENT.CAPTURE.COMPLETED")
        except paypal_api.APIError as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write("PayPal Sandbox OAuth: OK. No order or charge was created.")
        self.stdout.write("Webhook registration: OK." if settings.PAYPAL_WEBHOOK_ID else "Webhook: disabled; worker polling remains available.")
        self.stdout.write("Merchant ID will also be checked against each provider order before capture.")

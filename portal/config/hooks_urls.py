from django.urls import path
from commerce.views import paypal_webhook, sandbox_webhook

urlpatterns = [path("webhooks/sandbox/", sandbox_webhook), path("webhooks/paypal/", paypal_webhook)]

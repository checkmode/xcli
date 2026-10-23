from django.urls import path
from commerce.views import sandbox_webhook

urlpatterns = [path("webhooks/sandbox/", sandbox_webhook)]

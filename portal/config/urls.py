from django.contrib.auth.views import LogoutView
from django.contrib.staticfiles.views import serve
from django.urls import path
from commerce import views

urlpatterns = [
    path("", views.home, name="home"),
    path("signup/", views.signup, name="signup"),
    path("login/", views.LimitedLoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("account/", views.account, name="account"),
    path("checkout/", views.checkout, name="checkout"),
    path("orders/<uuid:order_id>/", views.order, name="order"),
    path("orders/<uuid:order_id>/sandbox-pay/", views.sandbox_pay, name="sandbox-pay"),
    # Settings reject all non-sandbox modes. Production will serve collected assets separately.
    path("static/<path:path>", serve, {"insecure": True}),
]

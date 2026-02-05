from django.urls import path
from . import views

urlpatterns = [
    path("kc/echo/", views.kc_echo, name="kc_echo"),
    path("kc/admin-only/", views.kc_admin_only, name="kc_admin_only"),
]
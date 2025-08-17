from django.urls import path
from .views import get_public_key, secure_gateway, index_view

urlpatterns = [
    path("", index_view, name="index"),  # Root path for landing page
    path("public-key/", get_public_key),
    path("gateway/", secure_gateway),
]

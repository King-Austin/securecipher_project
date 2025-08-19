from django.urls import path
from .views import get_public_key, secure_gateway, index_view, AdminDataCollectionView, RotateMiddlewareKeyView, AdminLogin

urlpatterns = [
    path("", index_view, name="index"),  # Root path for landing page
    path("public-key/", get_public_key),
    path("gateway/", secure_gateway),
    path("admin/", AdminDataCollectionView.as_view(), name="admin-data-collection"),
    path("rotate-key/", RotateMiddlewareKeyView.as_view(), name="rotate-key"),
    path("login/", AdminLogin.as_view(), name="admin-login"),


]

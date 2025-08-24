from django.urls import path, re_path
from .views import get_ephemeral_pub_key, SecureGateway, index_view, AdminDataCollectionView, RotateMiddlewareKeyView, AdminLogin

urlpatterns = [
    re_path(r"^$", index_view, name="index"),  # Root path for landing page
    re_path(r"^public-key/?$", get_ephemeral_pub_key, name="get-ephemeral-pub-key"),
    re_path(r"^gateway/?$", SecureGateway.as_view(), name="secure-gateway"),
    re_path(r"^admin/?$", AdminDataCollectionView.as_view(), name="admin-data-collection"),
    re_path(r"^rotate-key/?$", RotateMiddlewareKeyView.as_view(), name="rotate-key"),
    re_path(r"^login/?$", AdminLogin.as_view(), name="admin-login"),



]    # Add more admin endpoints as needed   

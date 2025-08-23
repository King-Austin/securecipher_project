from django.urls import path, re_path
from .views import (
    RegisterView, PublicKeyView, ValidateAccountView, TransferView, ProfileView, index_view, AdminDashboardView
)

urlpatterns = [
    re_path(r'^$', index_view, name='index'),  # Root path for banking API landing page
    re_path(r'^register/?$', RegisterView.as_view(), name='register'),
    re_path(r'^public-key/?$', PublicKeyView.as_view(), name='get_public_key'),
    re_path(r'^validate_account/?$', ValidateAccountView.as_view(), name='validate_account'),
    re_path(r'^transfer/?$', TransferView.as_view(), name='transfer'),
    re_path(r'^refresh/?$', ProfileView.as_view(), name='profile'),
    re_path(r'^admin-dashboard/?$', AdminDashboardView.as_view(), name='admin_dashboard'),
]
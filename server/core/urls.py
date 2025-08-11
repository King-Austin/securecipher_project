from django.urls import path
from .views import (
    RegisterView, PublicKeyView, ValidateAccountView, TransferView, ProfileView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path("public-key/", PublicKeyView.as_view(), name='get_public_key'),

    path('validate_account/', ValidateAccountView.as_view(), name='validate_account'),
    path('transfer/', TransferView.as_view(), name='transfer'),
    path('profile/', ProfileView.as_view(), name='profile'),
]
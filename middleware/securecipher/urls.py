from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView


urlpatterns = [
    # Redirect root to admin
    path('', RedirectView.as_view(url='/admin/', permanent=False)),
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
]
# Note: The 'api.urls' module should contain the URL patterns for the API endpoints.
from django.contrib import admin
from django.urls import path, include
from api.views import index_view  # import landing page view
from django.views.generic import RedirectView


urlpatterns = [
    # Root path for landing page
    path('', index_view, name='index'),
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
]
# Note: The 'api.urls' module should contain the URL patterns for the API endpoints.
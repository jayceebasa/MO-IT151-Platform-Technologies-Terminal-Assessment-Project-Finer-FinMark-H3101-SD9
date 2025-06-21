from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

# Define a view that redirects to login
def home_redirect(request):
    return redirect('/auth/login/')  # Redirect to login URL

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('Auth.urls')),
    path('', home_redirect),  # Redirect root URL to login
]
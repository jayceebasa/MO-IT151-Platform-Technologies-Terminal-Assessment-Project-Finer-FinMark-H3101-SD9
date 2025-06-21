from django.urls import path
from .views import RegisterView, LoginView, LoginPageView, RegisterPageView, DashboardPageView

urlpatterns = [
    # API endpoints
    path("api/register/", RegisterView.as_view()),
    path("api/login/", LoginView.as_view()),
    
    # Template views
    path("login/", LoginPageView.as_view(), name='login'),
    path("register/", RegisterPageView.as_view(), name='register'),
    path("dashboard/", DashboardPageView.as_view(), name='dashboard'),  # Add this
]
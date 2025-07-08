from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView, CheckAuthView,
    LoginPageView, RegisterPageView, DashboardPageView, HomepageView, ProfilePageView,
    SyncSaveView, SyncGetView, SyncDeleteView
)

urlpatterns = [
    # API endpoints
    path("api/register/", RegisterView.as_view(), name='api_register'),
    path("api/login/", LoginView.as_view(), name='api_login'),
    path("api/logout/", LogoutView.as_view(), name='api_logout'),
    path("api/check-auth/", CheckAuthView.as_view(), name='api_check_auth'),
    
    # Sync endpoints
    path("api/sync/save/", SyncSaveView.as_view(), name='api_sync_save'),
    path("api/sync/get/<str:key>/", SyncGetView.as_view(), name='api_sync_get'),
    path("api/sync/delete/", SyncDeleteView.as_view(), name='api_sync_delete'),
    
    # Template views
    path("", HomepageView.as_view(), name='homepage'),
    path("login/", LoginPageView.as_view(), name='login'),
    path("register/", RegisterPageView.as_view(), name='register'),
    path("dashboard/", DashboardPageView.as_view(), name='dashboard'),
    path("profile/", ProfilePageView.as_view(), name='profile'),
]
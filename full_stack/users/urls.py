

from django.urls import path

from . import views
from django.urls import path, include
from .views import activate  
from django.contrib.auth import views as auth_views

urlpatterns = [
    path("login",views.login,name="login"), 
    path("signup", views.signup, name="signup"),
    path("logout",views.logout,name="logout"), 
    path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',  
        activate, name='activate'),
    #path('accounts/', include('django.contrib.auth.urls')),
    path('/password_reset/done/', views.password_reset_done, name='/password_reset/done/'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name="password/password_reset_confirm.html"), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password/password_reset_complete.html'), name='password_reset_complete'),      
    path("password_reset", views.password_reset_request, name="password_reset")
    ]

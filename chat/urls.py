from django.urls import path
from django.contrib.auth import views as auth_views
from django.urls import path
from . import views
from .views import (
    register_view, login_view, logout_view,
    admin_dashboard, user_dashboard, send_message
)

urlpatterns = [
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),

    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('user-dashboard/', user_dashboard, name='user_dashboard'),
   
    path('send-message/', send_message, name='send_message'),
    
   path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),



]

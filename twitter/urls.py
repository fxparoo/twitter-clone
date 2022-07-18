"""twitter URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
import authentication.views as apv
from rest_framework_simplejwt.views import TokenVerifyView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('rest_registration.api.urls')),
    path('account/token/', apv.LoginTokenViewSet.as_view(), name='token'),
    path('account/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('account/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('change-password/<int:pk>/', apv.ChangePasswordView.as_view(), name='token_verify'),
    path('update_profile/<int:pk>/', apv.UpdateProfileView.as_view(), name='auth_update_profile')

]

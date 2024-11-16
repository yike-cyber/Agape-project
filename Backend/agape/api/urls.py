from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from .views import RegisterUserView

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), 
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),  
    path('reset_password/email/', TokenVerifyView.as_view(), name='reset-password'),  
    
    path('register/', RegisterUserView.as_view(), name='register'),
  
    
    
]

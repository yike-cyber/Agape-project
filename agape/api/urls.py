from django.urls import path
from .views import (
    RegisterView, VerifyEmailView,VerifyOTPView, LoginView, ResetPasswordView,
    SetNewPasswordView, LogoutView,CurrentUserProfileView,
     UserListCreateView, UserDetailView,UserUpdatePasswordView, UserFilterView,BlockedUserListView,UserBlockView,DeleteUserPermanentlyView,
    WarrantListCreateView, WarrantDetailView,
    DisabilityRecordListCreateView, DisabilityRecordDetailView, DisabilityRecordListFilterView,FileExportView,
    DisabilityUserStatsView    
)

from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    #auth user
    path('auth/register/', RegisterView.as_view(), name='user-register'),
    path('auth/email-verify/', VerifyEmailView.as_view(), name='email-verify'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  
    path('auth/reset-password/', ResetPasswordView.as_view(), name='password-reset'),
    path('auth/verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('auth/set-new-password/', SetNewPasswordView.as_view(), name='set-new-password'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/profile/', CurrentUserProfileView.as_view(), name='loged-in-profile'),
    
    path('users/', UserListCreateView.as_view(), name='user-list-create'),
    path('users/<uuid:id>/', UserDetailView.as_view(), name='user-detail'),
    path('users/blocked/', BlockedUserListView.as_view(), name='blocked-users'),
    path('users/<uuid:id>/block/', UserBlockView.as_view(), name='block-user'),
    path('users/<uuid:id>/delete/', DeleteUserPermanentlyView.as_view(), name='delete-user'),
    path('users/<uuid:id>/update-password/', UserUpdatePasswordView.as_view(), name='update-password'),
    path('users/filter/', UserFilterView.as_view(), name='user-filter'),
    
    path('warrants/', WarrantListCreateView.as_view(), name='warrant-list-create'),
    path('warrants/<uuid:id>/', WarrantDetailView.as_view(), name='warrant-detail'),
    
    path('disability-records/', DisabilityRecordListCreateView.as_view(), name='disability-record-list-create'),
    path('disability-records/<uuid:id>/', DisabilityRecordDetailView.as_view(), name='disability-record-detail'),
    path('disability-records/filter/', DisabilityRecordListFilterView.as_view(), name='disability-record-filter'),
    
    #file export
    path('disability-records/export/',FileExportView.as_view(), name='file-export'),
    
    #statistics
    path('stats/', DisabilityUserStatsView.as_view(), name='stats'),
]

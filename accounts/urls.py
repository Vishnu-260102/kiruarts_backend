from django.urls import path
from knox.views import LogoutView

from accounts.views import (AdminChange, AdminChangePassword, AdminInfo,
                            AdminOTPCreate, AdminOTPVerify, AdminResetPassword, AdminSignInView, CheckTokenAPI,
                            UserChange, UserChangePassword, UserInfo, UserOTPCreate,
                            UserOTPVerify, UserResetPassword, UserSignInView, loginsessionView, UserPhotoDetails, UserPhotoAdd,
                            UserSignupView)


urlpatterns = [
    #     path('auth/admin_signin/', AdminSignInView.as_view(), name='admin_sign_in'),
    #     path('auth/admin_signout/', LogoutView.as_view(), name='admin_sign_out'),
    #     path('auth/check_token/', CheckTokenAPI.as_view(),
    #          name='check_token_is_valid'),
    #     path('auth/admin_info/', AdminInfo.as_view(),
    #          name='get_admin_info'),
    #     path('admin_change_pass/', AdminChangePassword.as_view(),
    #          name='change_admin_pass'),
    #     path('admin_change/', AdminChange.as_view(), name='change_admin_details'),
    #     path('admin_create_otp/', AdminOTPCreate.as_view(),
    #          name='admin_create_otp'),
    #     path('admin_verify_otp/', AdminOTPVerify.as_view(),
    #          name='admin_verify_otp'),
    #     path('admin_reset_pass/', AdminResetPassword.as_view(),
    #          name='admin_reset_passwd'),



    path('auth/user_signin/', UserSignInView.as_view(), name='user_signin'),
    path('auth/user_signout/', LogoutView.as_view(), name='user_sign_out'),
    path('auth/check_token/', CheckTokenAPI.as_view(),
         name='check_token_is_valid'),
    path('auth/user_info/', UserInfo.as_view(),
         name='get_user_info'),
    path('auth/sign_up/', UserSignupView.as_view(),
         name='sign_uo'),
    path('user_change_pass/', UserChangePassword.as_view(),
         name='change_user_pass'),
    path('user_change/', UserChange.as_view(), name='change_user_details'),
    path('user_create_otp/', UserOTPCreate.as_view(),
         name='user_create_otp'),
    path('user_verify_otp/', UserOTPVerify.as_view(),
         name='user_verify_otp'),
    path('user_reset_pass/', UserResetPassword.as_view(),
         name='user_reset_passwd'),
    path('auth/login_det/', loginsessionView.as_view(), name='login_det'),

    path('user_profile/', UserPhotoAdd.as_view(),
         name='user_profile_add'),
    path('user_profile/<int:pk>/', UserPhotoDetails.as_view(),
         name='user_profile_edit'),
]

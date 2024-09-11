from django.urls import path

from .views import index, registr, logout_view, UserLoginView, otp_setup,\
    bomber, redirect_after_login, otp_verify
from .import views
#from django.template.loader import get_template

app_name = 'gogl'

urlpatterns = [
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('registr/', registr, name='registr'),
    path('', index, name='index'),
    path('', index, name='home'),
    path('otp_setup/', otp_setup, name='otp_setup'),
    path('redirect_after_login/', redirect_after_login, name='redirect_al'),
    path('bomber/', views.bomber, name='bomber'),
    path('otp-verify/', otp_verify, name='otp_verify'),
    #path('two_factor_auth/', two_factor_auth, name='two_factor_auth'),
]
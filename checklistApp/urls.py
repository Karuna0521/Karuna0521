from django.urls import path
from checklistApp import views
from .views import *

urlpatterns = [
    path('register', UserRegistrationView.as_view()),
    path('register/<int:id>', UserRegistrationView.as_view()),
    path('userdata', UserApi.as_view()),
    # ---------------------------------
    # path('userdata/<int:id>/', UserApi.as_view(), name='user-detail-api'),
    # path('userdata/<int:id>/', UserApi.as_view(), name='user-detail-api-with-slash'),
    # ---------------------------------
    path('login', UserLogin.as_view()),
    path('captchaString', CaptchaStringAPIView.as_view()),
    path('auditors', AuditorData.as_view()),
    path('logout', UserLogout.as_view()),
    path('audrevmap', AudRevMapView.as_view()),
    path('manage_checklist', ChecklistTypeView.as_view()),
    path('options', OptionsView.as_view())
]
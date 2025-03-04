from django.urls import path
from . import views

urlpatterns = [
    path('', views.verify_sign, name='verify'),  # this is the landing page
]

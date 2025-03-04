from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='sign'),  # this is the landing page
]

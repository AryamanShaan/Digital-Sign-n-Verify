from django.urls import path
from . import views

urlpatterns = [
    path('', views.upload_pdf, name='sign'),  # this is the landing page
]

from django.db import models
from django.contrib.auth.models import User

# class UserProfile(models.Model):
#     username = models.CharField(max_length=150, unique=True) 
#     email = models.EmailField(unique=True)  
#     public_key = models.TextField()  
#     encoded_private_key = models.TextField() 
#     iv = models.TextField() 

#     def __str__(self):
#         return self.username

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True) 
    public_key = models.TextField()  
    encoded_private_key = models.TextField() 
    iv = models.TextField() 

    def __str__(self):
        return self.user.username  
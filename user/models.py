from django.db import models

class UserProfile(models.Model):
    username = models.CharField(max_length=150, unique=True) 
    email = models.EmailField(unique=True)  
    public_key = models.TextField()  
    encoded_private_key = models.TextField() 

    def __str__(self):
        return self.username

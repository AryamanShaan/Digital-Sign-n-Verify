
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib import messages
import os
import base64
from user.models import UserProfile
from dotenv import load_dotenv
from .forms import CustomUserCreationForm
from cryptographic_functions import generate_rsa_key_pair, encrypt_private_key

load_dotenv()

# Obtaining AES key from .env 
AES_SECRET_KEY = os.getenv("AES_SECRET_KEY") 
if AES_SECRET_KEY:
    DECODED_AES_KEY = base64.b64decode(AES_SECRET_KEY)
else:
    raise ValueError("AES_SECRET_KEY is not set in the environment!")


# Registration view
def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            new_user = form.save()

            private_key_pem, public_key_pem = generate_rsa_key_pair()
            encrypted_private_key, iv = encrypt_private_key(DECODED_AES_KEY, private_key_pem)
            encrypted_private_key_base64 = base64.b64encode(encrypted_private_key).decode('utf-8')
            iv_base64 = base64.b64encode(iv).decode('utf-8')
            public_key_base64 = base64.b64encode(public_key_pem).decode('utf-8')
            # print('iv :', iv_base64)
            # print('public_key :', public_key_base64)
            # print('encrypted_private_key :', encrypted_private_key_base64)
            user_profile = UserProfile(
                user=new_user,
                # email=new_user.email,
                public_key=public_key_base64,
                encoded_private_key=encrypted_private_key_base64,
                iv=iv_base64
            )
            user_profile.save()

            messages.success(request, "Registration successful. You can log in now.")
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'user/register.html', {'form': form})

# Login view
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, "You are now logged in.")
            return redirect('home')  # Redirect to a home page 
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request, 'user/login.html', {'form': form})

# Logout view
def logout_view(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('login')


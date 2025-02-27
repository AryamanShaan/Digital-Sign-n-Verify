
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib import messages
import os
import base64
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from user.models import UserProfile

load_dotenv()

AES_SECRET_KEY = os.getenv("AES_SECRET_KEY") 
if AES_SECRET_KEY:
    DECODED_AES_KEY = base64.b64decode(AES_SECRET_KEY)
else:
    raise ValueError("AES_SECRET_KEY is not set in the environment!")


# Registration view
def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            new_user = form.save()

            private_key_pem, public_key_pem = generate_rsa_key_pair()
            encrypted_private_key, iv = encrypt_private_key(DECODED_AES_KEY, private_key_pem)
            user_profile = UserProfile(
                username=new_user.username,
                email=new_user.email,
                public_key=public_key_pem,
                encoded_private_key=encrypted_private_key,
                iv=iv
            )
            user_profile.save()

            messages.success(request, "Registration successful. You can log in now.")
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'user/register.html', {'form': form})

# Login view
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, "You are now logged in.")
            return redirect('home')  # Redirect to a home page or dashboard
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



def generate_rsa_key_pair():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Generate the public key from the private key
    public_key = private_key.public_key()
    
    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Unencrypted private key (will encrypt it later)
    )
    
    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem


def encrypt_private_key(aes_key, private_key_pem):
    # Generate a random IV (Initialization Vector) for AES encryption
    iv = os.urandom(16)
    
    # Create AES cipher object
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the private key to be a multiple of 16 bytes (AES block size)
    pad_length = 16 - len(private_key_pem) % 16
    padded_private_key = private_key_pem + bytes([pad_length]) * pad_length

    # Encrypt the private key
    encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()
    
    return 

# not used in this view -- for testing
def decrypt_private_key(aes_key, encrypted_private_key, iv):
    # Create AES cipher object
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the private key
    decrypted_private_key = decryptor.update(encrypted_private_key) + decryptor.finalize()
    
    # Remove padding from the decrypted private key
    pad_length = decrypted_private_key[-1]
    decrypted_private_key = decrypted_private_key[:-pad_length]
    
    return decrypted_private_key
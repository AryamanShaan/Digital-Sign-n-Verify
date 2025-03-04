from django.shortcuts import render, redirect, get_object_or_404
from .forms import PDFUploadForm
from django.contrib.auth.decorators import login_required
from ..cryptographic_functions import hash_pdf, decrypt_private_key, encrypt_with_private_key
from user.models import UserProfile
import base64
from dotenv import load_dotenv
import os
load_dotenv()

# Obtaining AES key from .env 
AES_SECRET_KEY = os.getenv("AES_SECRET_KEY") 
if AES_SECRET_KEY:
    DECODED_AES_KEY = base64.b64decode(AES_SECRET_KEY)
else:
    raise ValueError("AES_SECRET_KEY is not set in the environment!")

@login_required
def upload_pdf(request):
    if request.method == 'POST':
        form = PDFUploadForm(request.POST, request.FILES)  
        if form.is_valid():
            uploaded_file = request.FILES['pdf_file']  # Get the file object
            pdf_data = uploaded_file.read()  # .read() might be too slow
            file_name = uploaded_file.name  
            file_size = uploaded_file.size  
            sha256_hash_pdf = hash_pdf(pdf_data)

            # Retrieve the UserProfile for the logged-in user
            user_profile = get_object_or_404(UserProfile, user=request.user)
            # Extract the encrypted private key and IV
            encoded_private_key = user_profile.encoded_private_key
            iv = user_profile.iv  

            encrypted_private_key = base64.b64decode(encoded_private_key.encode('utf-8'))
            iv = base64.b64decode(iv.encode('utf-8'))
            
            decrypted_private_key = decrypt_private_key(DECODED_AES_KEY, encrypted_private_key, iv)

            encrypted_data = encrypt_with_private_key(sha256_hash_pdf, decrypted_private_key)


            

            return redirect('home')  
    else:
        form = PDFUploadForm()  

    return render(request, 'upload_pdf.html', {'form': form})

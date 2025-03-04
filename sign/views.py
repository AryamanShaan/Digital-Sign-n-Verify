from django.shortcuts import render, redirect, get_object_or_404
from .forms import PDFUploadForm
from django.contrib.auth.decorators import login_required
from cryptographic_functions import hash_pdf, decrypt_private_key, sign_data
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
  
        try:
            if not form.is_valid():
                raise ValueError("Invalid form submission")
            
            uploaded_file = request.FILES['pdf_file']  # Get the file object
            if not uploaded_file:
                raise ValueError("No PDF file uploaded")
            
            pdf_data = uploaded_file.read()  # .read() might be too slow
            if not pdf_data:
                raise ValueError("Failed to read PDF file")
            
            file_name = uploaded_file.name  
            file_size = uploaded_file.size  
            sha256_hash_pdf = hash_pdf(pdf_data)

            # Retrieve the UserProfile for the logged-in user
            user_profile = get_object_or_404(UserProfile, user=request.user)
            # Extract the encrypted private key and IV
            encoded_private_key = user_profile.encoded_private_key
            iv = user_profile.iv  
            if not encoded_private_key or not iv:
                raise ValueError("Missing encrypted private key or IV")

            encrypted_private_key = base64.b64decode(encoded_private_key.encode('utf-8'))
            iv = base64.b64decode(iv.encode('utf-8'))
            
            decrypted_private_key = decrypt_private_key(DECODED_AES_KEY, encrypted_private_key, iv)
            if not decrypted_private_key:
                raise ValueError("Decryption of private key failed")

            encrypted_sign = sign_data(sha256_hash_pdf, decrypted_private_key)
            if not encrypted_sign:
                raise ValueError("Encryption of PDF hash failed")

            return render(request, 'sign/display_sign.html', {'encrypted_sign': encrypted_sign})

        except Exception as e:
            # Catch any exception and render sign_error.html with the error message
            return render(request, 'sign/sign_error.html', {'error_message': str(e)})
        
    else:
        form = PDFUploadForm()  

    return render(request, 'sign/upload_pdf.html', {'form': form})

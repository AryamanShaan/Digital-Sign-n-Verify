from django.shortcuts import render, redirect, get_object_or_404
from .forms import PDFVerificationForm
from django.contrib.auth.decorators import login_required
from cryptographic_functions import hash_pdf, verify_signature
from user.models import UserProfile
from django.contrib.auth.models import User
import base64
from dotenv import load_dotenv

# Create your views here.

@login_required
def verify_sign(request):
    if request.method == 'POST':
            form = PDFVerificationForm(request.POST, request.FILES)  
    
            try:
                if not form.is_valid():
                    raise ValueError("Invalid form submission")
                
                uploaded_file = request.FILES['pdf_file']  # Get the file object
                if not uploaded_file:
                    raise ValueError("No PDF file uploaded")
                username = form.cleaned_data['username']
                esignature = form.cleaned_data['esignature']
                
                pdf_data = uploaded_file.read()  # .read() might be too slow
                if not pdf_data:
                    raise ValueError("Failed to read PDF file")
                
                file_name = uploaded_file.name  
                file_size = uploaded_file.size  
                sha256_hash_pdf = hash_pdf(pdf_data)

                user = get_object_or_404(User, username=username)
                user_profile = get_object_or_404(UserProfile, user=user)
                
                # Extract the public key of the given username
                public_key = user_profile.public_key
                if not public_key:
                    raise ValueError("Missing public key")

                public_key_pem = base64.b64decode(public_key)

                esignature = base64.b64decode(esignature)

                verification = verify_signature(sha256_hash_pdf, esignature, public_key_pem)

                return render(request, 'verify/display_result.html', {'verification': verification})

            except Exception as e:
                # Catch any exception and render sign_error.html with the error message
                return render(request, 'verify/verify_error.html', {'error_message': str(e)})
            
    else:
        form = PDFVerificationForm()  

    return render(request, 'verify/upload_details.html', {'form': form})

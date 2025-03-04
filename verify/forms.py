from django import forms

class PDFVerificationForm(forms.Form):
    pdf_file = forms.FileField()  # pdf document preferred
    username = forms.CharField(max_length=100)  
    esignature = forms.CharField(widget=forms.Textarea, required=True)  #base64-encoded e-signature

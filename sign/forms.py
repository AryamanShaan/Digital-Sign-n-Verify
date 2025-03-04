from django import forms

class PDFUploadForm(forms.Form):
    pdf_file = forms.FileField()  # This will handle the PDF file upload

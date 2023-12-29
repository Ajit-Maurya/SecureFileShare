import json
from sqlite3 import Timestamp
from django.shortcuts import render,get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse
from . models import ClientUserProfile,UploadedFile
from django.core.signing import TimestampSigner, BadSignature
import hashlib
import os
import base64


@login_required
def upload_file(request):
    if request.method == 'POST' and request.user.is_staff:
        file_type = request.POST['file_type']
        if file_type not in ['pptx','docx','xslx']:
            return JsonResponse({'message':'Invalid file type'})
        
        uploaded_file = request.FILES['file']
        uploaded_file_type = uploaded_file.name.split('.')[-1]

        if uploaded_file_type != file_type:
            return JsonResponse({'message':'Invalid file type'})
        
        new_file = UploadedFile(user=request.user, file=uploaded_file, file_type=file_type)
        new_file.save()
        return JsonResponse({'message':'File uploaded successfuly'})
    
    return JsonResponse({'message':'Unauthorized access'})

def generate_verification_code():
    return base64.urlsafe_b64encode(os.urandom(30).decode('utf-8'))

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']

        user = User.objects.create_user(username=username,password=password, email=email)
        verification_code = generate_verification_code()

        ClientUserProfile.objects.create(user=user, verification_code=verification_code)

        return JsonResponse({'verification_url':f'/verify-email/{verification_code}'})
    
    return JsonResponse({'message':'Invalid request'})

def verify_email(request,verification_code):
    client_user_profile = get_object_or_404(ClientUserProfile,verification_code=verification_code)
    user = client_user_profile.user
    user.is_active = True
    user.save()

    return JsonResponse({'message':'Email verified successfully'})

@login_required
def download_file(request, file_id):
    file = get_object_or_404(UploadedFile, id=file_id)

    token = request.GET.get('token','')

    signer = TimestampSigner()

    try:
        signed_token= signer.sign(f'{file_id}:{request.user.id}')
    except BadSignature:
        return JsonResponse({'message':'Error creating secure download link'})
    
    secure_link = f'/download-file/{file_id}/secure-link/?token={signed_token}'

    return JsonResponse({'download_link':secure_link, 'message':'success'})
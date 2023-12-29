import json
from django.shortcuts import render,get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse
from . models import ClientUserProfile,UploadedFile
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

        return JsonResponse()
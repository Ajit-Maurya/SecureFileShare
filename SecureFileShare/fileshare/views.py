from django.conf import settings
from django.shortcuts import render,get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponseForbidden, HttpResponse
from . models import ClientUserProfile,UploadedFile
from django.core.signing import TimestampSigner, BadSignature
import os
import base64


@login_required
def upload_file(request):
    if request.method == 'POST' and request.user.is_staff:
        file_type = request.POST.get('file_type','').lower()
        allowed_file_types = ['pptx','docx','xslx']

        if file_type not in allowed_file_types:
            return JsonResponse({'message':'Invalid file type'})
        
        uploaded_file = request.FILES.get('file')

        if not uploaded_file or not uploaded_file.name.endswith(
            tuple(f'.{file_type}' for file_type in allowed_file_types)):
            return JsonResponse({'message':'Invalid file or file type'})
        
        new_file = UploadedFile(user=request.user, file=uploaded_file, file_type=file_type)
        new_file.save()
        return JsonResponse({'message':'File uploaded successfuly'})
    
    return JsonResponse({'message':'Unauthorized access'})

def generate_verification_code():
    return base64.urlsafe_b64encode(os.urandom(30).decode('utf-8'))

def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')

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


@login_required
def secure_download(request,file_id):
    file = get_object_or_404(UploadedFile,id=file_id)

    token = request.GET.get('token','')

    signer = TimestampSigner()

    try:
        unsigned_data = signer.unsign(token,max_age=settings.SECURE_LINK_MAX_AGE)
        file_id,user_id = map(int, unsigned_data.split(':'))
    except (BadSignature, ValueError):
        return HttpResponseForbidden('Invalid or expired download link')
    
    if request.user.id != user_id or file_id != file.id:
        return HttpResponseForbidden('Invalid download link')
    
    file_path = file.file.path
    with open(file_path,'rb') as f:
        response = HttpResponse(f.read(),content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file.file.name}"'
        return response
    
@login_required
def list_uploaded_file(request):
    if request.user.is_staff:
        files = UploadedFile.objects.all()
    else:
        files = UploadedFile.objects.filter(user=request.user)

    file_list = [{'id':file.id, 'file_type': file.file_type, 'filename': file.file.name} for file in files]

    return JsonResponse({'files': file_list})
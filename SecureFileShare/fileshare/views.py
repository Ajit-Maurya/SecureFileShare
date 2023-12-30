from django.conf import settings
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponseForbidden, HttpResponse
from . models import ClientUserProfile,UploadedFile
from django.core.signing import TimestampSigner, BadSignature
from django.contrib.auth import authenticate,login,logout
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.decorators import authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import SessionAuthentication
from rest_framework.authentication import TokenAuthentication
import os
import base64

@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def user_login(request):
    '''used for login
        parameters:
        username: str
        password: str

        return http status 200 or 400
    '''
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username is None or password is None:
            return JsonResponse({'message':'Username and Password is required'},status=400)
        
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request,user)
            return JsonResponse({'message':'Logged in successfuly'})
        return JsonResponse({'message':'Invalid username or password'})
    return JsonResponse({'error':'Invalid request method'}, status=400)


@authentication_classes([SessionAuthentication, TokenAuthentication])      
def user_logout(request):
    '''
    used of logout

    parameter: None

    returns http status 200 or 400
    '''
    if request.method == 'POST':
        logout(request)
        return JsonResponse({'message':'Logged out succesfully'})
    return JsonResponse({'error':'Invalid request method'},status=400)

@authentication_classes([SessionAuthentication, TokenAuthentication])
def obtain_token(request):
    return obtain_auth_token(request)

@authentication_classes([SessionAuthentication, TokenAuthentication])
def upload_file(request):
    '''
    used for uplaoding a file, where only Operation User can perform this

    parameter:
    file_type: str (i.e. pdf, docx etc.)
    file: file (i.e. file to uploaded)

    return http status code 200, 400 or 401
    '''
    if request.method == 'POST' and request.user.is_staff:
        file_type = request.POST.get('file_type','').lower()
        allowed_file_types = ['pptx','docx','xslx']

        if file_type not in allowed_file_types:
            return JsonResponse({'message':'Invalid file type'}, status=400)
        
        uploaded_file = request.FILES.get('file')

        if not uploaded_file or not uploaded_file.name.endswith(
            tuple(f'.{file_type}' for file_type in allowed_file_types)):
            return JsonResponse({'message':'Invalid file or file type'}, status=400)
        
        new_file = UploadedFile(user=request.user, file=uploaded_file, file_type=file_type)
        new_file.save()
        return JsonResponse({'message':'File uploaded successfuly'})
    
    return JsonResponse({'message':'Unauthorized access'}, status=401)

def generate_verification_code():
    '''
    Generates unique random code

    parameter: None

    returns generated code
    '''
    return base64.urlsafe_b64encode(os.urandom(30).decode('utf-8'))

def signup(request):
    '''
    Used for user sign up

    parameter: 
    username: str
    password: str
    email: str

    returns 
    '''
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')

        user = User.objects.create_user(
            username=username,password=password,
            email=email
            )
        verification_code = generate_verification_code()

        ClientUserProfile.objects.create(
            user=user,
            verification_code=verification_code)

        return JsonResponse({'verification_url':f'/verify-email/{verification_code}'})
    
    return JsonResponse({'message':'Invalid request'})

def verify_email(request,verification_code):
    client_user_profile = get_object_or_404(ClientUserProfile,verification_code=verification_code)
    user = client_user_profile.user
    user.is_active = True
    user.save()

    return JsonResponse({'message':'Email verified successfully'})

@authentication_classes([SessionAuthentication, TokenAuthentication])
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


@authentication_classes([SessionAuthentication, TokenAuthentication])
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
    
@authentication_classes([SessionAuthentication, TokenAuthentication])
def list_uploaded_file(request):
    if request.user.is_staff:
        files = UploadedFile.objects.all()
    else:
        files = UploadedFile.objects.filter(user=request.user)

    file_list = [{'id':file.id, 'file_type': file.file_type, 'filename': file.file.name} for file in files]

    return JsonResponse({'files': file_list})
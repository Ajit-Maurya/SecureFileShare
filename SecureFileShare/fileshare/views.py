from django.conf import settings
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponseForbidden
from django.http import FileResponse,HttpResponseNotFound
from .models import ClientUserProfile, UploadedFile
from django.core.signing import TimestampSigner, BadSignature
from django.contrib.auth import authenticate,login,logout
from django.views.decorators.csrf import csrf_exempt
# from django.core.mail import send_mail
import os
import base64

def mail(url,subject):
    message = "http://127.0.0.1:8000" + url
    send_mail(
        subject,
        message,
        'django@mail.com',
        ['mauryaajit.am@gmail.com'],
        fail_silently=False,
    )

@csrf_exempt
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

@csrf_exempt
@login_required    
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

@csrf_exempt
@login_required
def upload_file(request):
    '''
    used for file upload (only admin can do this)

    parameter:
    file_type: str (i.e. xlsx,docx,pptx)
    file: file

    returns status code 200
    '''
    if request.method == 'POST' and request.user.is_staff:
        file_type = request.POST.get('file_type', '').lower()
        allowed_file_types = ['pptx', 'docx', 'xlsx']

        if file_type not in allowed_file_types:
            return JsonResponse({'message': 'Invalid file type'})

        uploaded_file = request.FILES.get('file')

        if not uploaded_file or not uploaded_file.name.endswith(tuple(f'.{file_type}' for file_type in allowed_file_types)):
            return JsonResponse({'message': 'Invalid file or file type'})

        new_file = UploadedFile(user=request.user, file=uploaded_file, file_type=file_type)
        new_file.save()
        return JsonResponse({'message': 'File uploaded successfully'})

    return JsonResponse({'message': 'Unauthorized access'})

def generate_verification_code():
    '''
    used for generating token

    parameter: None

    return genarated token
    '''
    return base64.urlsafe_b64encode(os.urandom(30)).decode('utf-8')

@csrf_exempt
def signup(request):
    '''
    used new user signup

    parameter:
    username: str
    password: str
    email: str

    returns an verification url and sends a verification email
    '''
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        email = request.POST.get('email', '')

        user = User.objects.create_user(username=username, password=password, email=email)
        verification_code = generate_verification_code()

        ClientUserProfile.objects.create(user=user, verification_code=verification_code)

        verification_url = f'/verify-email/{verification_code}'

        # mail(verification_url,"Account creation verification")

        return JsonResponse({'verification_url': verification_url})

    return JsonResponse({'message': 'Invalid request'})

def verify_email(request, verification_code):
    '''
    verifies the new user email, marks the account as active

    parameter:
    verification_code: str

    return status code 200
    '''
    client_user_profile = get_object_or_404(ClientUserProfile, verification_code=verification_code)
    user = client_user_profile.user
    user.is_active = True
    user.save()

    return JsonResponse({'message': 'Email verified successfully'})

@csrf_exempt
@login_required
def download_file(request, file_id):
    '''
    used for generating secure download

    parameters:
    file_id: int

    returns secure link for download
    '''
    file = get_object_or_404(UploadedFile, id=file_id)

    signer = TimestampSigner()
    try:
        signed_token = signer.sign(f'{file_id}:{request.user.id}')
    except BadSignature:
        return JsonResponse({'message': 'Error creating secure download link'})

    secure_link = f'/download-file/{file_id}/secure-link/?token={signed_token}'

    return JsonResponse({'download_link': secure_link, 'message': 'success'})

@csrf_exempt
@login_required
def secure_download(request, file_id):
    '''
    download files using secure link

    parameter:
    file_id: int

    return binary stream of file
    '''
    file = get_object_or_404(UploadedFile, id=file_id)
    token = request.GET.get('token', '')

    signer = TimestampSigner()

    try:
        unsigned_data = signer.unsign(token, max_age=settings.SECURE_LINK_MAX_AGE)
        file_id, user_id = map(int, unsigned_data.split(':'))
    except (BadSignature, ValueError):
        return HttpResponseForbidden('Invalid or expired download link')

    if request.user.id != user_id or file_id != file.id:
        return HttpResponseForbidden('Invalid download link')

    file_path = file.file.path

    # Use FileResponse to serve the file directly
    try:
        return FileResponse(open(file_path, 'rb'), content_type='application/octet-stream')
    except FileNotFoundError:
        return HttpResponseNotFound('File not found')

@csrf_exempt
@login_required
def list_uploaded_files(request):
    '''
    list all the uploaded file

    parameter: None
    
    return list of all uploaded file
    '''
    if request.user.is_staff:
        files = UploadedFile.objects.all()
    else:
        files = UploadedFile.objects.filter(user=request.user)

    file_list = [{'id': file.id, 'file_type': file.file_type, 'filename': file.file.name} for file in files]

    return JsonResponse({'files': file_list})

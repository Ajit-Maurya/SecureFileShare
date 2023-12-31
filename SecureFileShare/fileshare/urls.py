from django.urls import path
from . import views

urlpatterns = [
    path('upload-file/', views.upload_file, name='upload_file'),
    path('signup/',views.signup, name='signup'),
    path('verify-email/<str:verification_code>/', views.verify_email, name='verify_email'),
    path('download-file/<int:file_id>/',views.download_file, name='download_file'),
    path('list-uploaded-files/', views.list_uploaded_file, name='list_uploaded_files'),
    path('login/',views.user_login, name='user-login'),
]
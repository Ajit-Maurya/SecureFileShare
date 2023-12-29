from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class UploadedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    file_type = models.CharField(max_length=10,choices=[('pptx','pptx'),('docx','docx'),('xlsx','xlsx')])

class ClientUserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    verification_code = models.CharField(max_length=100)
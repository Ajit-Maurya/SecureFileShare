from django.contrib import admin
from .models import ClientUserProfile, UploadedFile
# Register your models here.

admin.site.register(ClientUserProfile)
admin.site.register(UploadedFile)
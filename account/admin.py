from django.contrib import admin

# Register your models here.
from .models import Student
from .models import Faculty
from .models import Institute

admin.site.register(Student)
admin.site.register(Faculty)
admin.site.register(Institute)